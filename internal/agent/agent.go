// Package agent — часть leauth, работающая на прокси-сервере:
// заказывает сертификаты в центре, забирает их и настраивает nginx.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"leauth/internal/api"
)

type Agent struct {
	cfg    *Config
	client *api.Client
	certs  *CertDir
	nginx  NginxController
	// nginxStopped закрывается, когда nginx перестал работать.
	nginxStopped <-chan error
	// waiting — последнее известное состояние ожидания сертификатов.
	// Нужно только для того, чтобы смена режима опроса попадала в лог
	// один раз, а не при каждой синхронизации.
	waiting bool
}

func New(cfg *Config, nginx NginxController) (*Agent, error) {
	if cfg == nil {
		return nil, errors.New("не передан конфиг агента")
	}

	return &Agent{
		cfg:   cfg,
		certs: NewCertDir(cfg.CertDir),
		nginx: nginx,
	}, nil
}

// tokenPath — где лежит выданный центром токен. Рядом с сертификатами:
// это тот же том, который переживает пересоздание контейнера.
func (a *Agent) tokenPath() string {
	return filepath.Join(a.cfg.CertDir, "client-token")
}

// ensureToken представляет прокси центру. При первом запуске прокси
// обменивает общий токен приёма на персональный и сохраняет его —
// добавление прокси не требует действий на стороне центра.
func (a *Agent) ensureToken(ctx context.Context) error {
	if a.client != nil {
		return nil
	}

	token, err := readToken(a.tokenPath())
	if err != nil {
		return err
	}

	if token == "" {
		if a.cfg.EnrollToken == "" {
			return errors.New("прокси не представлялся центру, а enroll_token не задан")
		}

		token, err = api.Enroll(ctx, a.cfg.Server, a.cfg.EnrollToken, a.cfg.Name)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(a.cfg.CertDir, 0o755); err != nil {
			return fmt.Errorf("каталог для токена: %w", err)
		}
		if err := writeAtomic(a.tokenPath(), []byte(token), 0o600); err != nil {
			return err
		}

		slog.Info("прокси принят центром", "имя", a.cfg.Name)
	}

	a.client = api.NewClient(a.cfg.Server, token)
	return nil
}

// readToken возвращает пустую строку, если токена ещё нет.
func readToken(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("чтение токена %s: %w", path, err)
	}
	return strings.TrimSpace(string(raw)), nil
}

// Bootstrap готовит прокси к работе до первого обращения к центру:
// создаёт заглушки, пишет конфиг и поднимает nginx. Прокси начинает
// отвечать сразу, пусть и самоподписанным сертификатом.
func (a *Agent) Bootstrap(ctx context.Context) error {
	// Порты публикует docker, а знает их только agent.yaml. Забытый в
	// compose порт даёт прокси, который поднялся и работает, но снаружи
	// не отвечает, — и ничем другим об этом не сообщается.
	slog.Info("nginx займёт порты — они должны быть опубликованы наружу",
		"порты", a.cfg.ListenPorts())

	for _, c := range a.cfg.Certificates() {
		if a.certs.Usable(c.Domain) {
			continue
		}

		certPEM, keyPEM, err := GenerateSelfSigned(c.Names()...)
		if err != nil {
			return err
		}
		if err := a.certs.Write(c.Domain, certPEM, keyPEM); err != nil {
			return err
		}

		slog.Info("создана самоподписанная заглушка", "сертификат", c.Domain, "имена", c.Names())
	}

	if err := a.nginx.WriteConfig(a.cfg); err != nil {
		return err
	}

	// oauth2-proxy поднимается до nginx: пока он не отвечает, закрытые
	// эндпоинты возвращают ошибку, а не пускают без авторизации.
	StartOAuthProxies(ctx, a.cfg)

	stopped, err := a.nginx.Start(ctx)
	if err != nil {
		return err
	}
	a.nginxStopped = stopped

	return nil
}

// WaitingInterval — как часто прокси спрашивает центр, пока хотя бы один
// домен живёт на самоподписанной заглушке. Ожидание тут измеряется
// минутами: человек дописал CNAME, центр выпустил сертификат — и незачем
// держать прокси на заглушке до конца часа.
const WaitingInterval = time.Minute

// Run поднимает прокси и дальше синхронизируется с центром по таймеру.
// Возвращает управление, когда контекст отменён или упал nginx.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.Bootstrap(ctx); err != nil {
		return err
	}

	for {
		a.Sync(ctx)

		select {
		case <-ctx.Done():
			return nil

		// Прокси без nginx ничего не обслуживает. Молча продолжать опрос
		// центра значило бы держать контейнер «живым» и не отвечающим,
		// поэтому агент завершается — перезапуск поднимет nginx заново.
		case err := <-a.nginxStopped:
			if ctx.Err() != nil {
				return nil
			}
			if err == nil {
				return errors.New("nginx завершился")
			}
			return fmt.Errorf("nginx завершился: %w", err)

		case <-time.After(a.pollDelay()):
		}
	}
}

// pollDelay возвращает паузу до следующей синхронизации: короткую, пока
// ждём настоящие сертификаты, и заданную в конфиге, когда всё на месте.
func (a *Agent) pollDelay() time.Duration {
	interval := a.cfg.PollInterval.Duration()
	if interval <= WaitingInterval {
		return interval
	}

	waiting := a.waitingForCerts()
	if waiting != a.waiting {
		a.waiting = waiting

		if waiting {
			slog.Info("ждём настоящий сертификат", "опрос центра", WaitingInterval)
		} else {
			slog.Info("все сертификаты выпущены", "опрос центра", interval)
		}
	}

	if waiting {
		return WaitingInterval
	}
	return interval
}

// waitingForCerts — остался ли хоть один домен на заглушке.
func (a *Agent) waitingForCerts() bool {
	for _, c := range a.cfg.Certificates() {
		if a.certs.SelfSigned(c.Domain) {
			return true
		}
	}
	return false
}

// Sync объявляет центру желаемое состояние прокси одним запросом и
// раскладывает то, что пришло в ответ.
//
// Ошибки наружу не выходят намеренно: недоступность центра не повод
// останавливать прокси — на диске лежат рабочие сертификаты со сроком до
// девяноста дней, и уронить из-за этого nginx было бы куда хуже, чем
// подождать следующего опроса.
func (a *Agent) Sync(ctx context.Context) {
	if err := a.ensureToken(ctx); err != nil {
		slog.Error("прокси не смог представиться центру", "ошибка", err)
		return
	}

	resp, err := a.client.Sync(ctx, a.wanted())
	if err != nil {
		slog.Error("синхронизация с центром не удалась", "ошибка", err)
		return
	}

	changed := false
	for _, d := range resp.Domains {
		a.report(d)

		if d.Cert == nil {
			continue
		}
		if err := a.certs.Write(d.Domain, []byte(d.Cert.FullChain), []byte(d.Cert.PrivateKey)); err != nil {
			slog.Error("не удалось записать сертификат", "домен", d.Domain, "ошибка", err)
			continue
		}

		slog.Info("сертификат обновлён",
			"домен", d.Domain,
			"serial", d.Cert.Serial,
			"до", d.Cert.NotAfter)

		changed = true
	}

	if !changed {
		return
	}

	if err := a.nginx.Reload(); err != nil {
		slog.Error("не удалось перезагрузить nginx", "ошибка", err)
		return
	}

	slog.Info("nginx перезагружен с новыми сертификатами")
}

// wanted собирает желаемое состояние: какие сертификаты нужны прокси
// и что у него уже есть. Серийники нужны, чтобы центр не присылал
// неизменившиеся сертификаты каждый час. Нечитаемый файл даёт пустой
// серийник — центр пришлёт сертификат заново и тем починит его.
func (a *Agent) wanted() []api.SyncCertificate {
	certs := a.cfg.Certificates()

	out := make([]api.SyncCertificate, 0, len(certs))
	for _, c := range certs {
		out = append(out, api.SyncCertificate{
			Domain:   c.Domain,
			Wildcard: c.Wildcard,
			Serial:   a.certs.Serial(c.Domain),
		})
	}
	return out
}

// report пишет в лог то, что требует вмешательства человека: CNAME
// и ошибки выпуска. Это единственное, чего система от него ждёт.
func (a *Agent) report(d api.SyncDomain) {
	switch d.Status {
	case api.StatusPendingCNAME:
		slog.Warn("нужен CNAME — сертификат не будет выпущен, пока запись не появится в зоне",
			"домен", d.Domain,
			"запись", d.CNAME.Name,
			"значение", d.CNAME.Target)
	case api.StatusError:
		slog.Error("центр не смог выпустить сертификат", "домен", d.Domain, "ошибка", d.LastError)
	}
}
