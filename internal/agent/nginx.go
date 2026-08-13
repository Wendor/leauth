package agent

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
)

//go:embed nginx.conf.tmpl
var nginxTmplText string

var nginxTmpl = template.Must(template.New("nginx").Parse(nginxTmplText))

// NginxController отделяет агента от настоящего nginx, чтобы цикл
// синхронизации можно было проверить тестами.
//
// Start возвращает канал, который закрывается, когда nginx перестал
// работать. Прокси без nginx бесполезен, поэтому агент обязан заметить
// это и завершиться — контейнер поднимет обоих заново.
type NginxController interface {
	WriteConfig(cfg *Config) error
	Start(ctx context.Context) (<-chan error, error)
	Reload() error
}

// DefaultResolver — встроенный DNS Docker: прокси всегда работает
// в контейнере, и апстримы адресуются именами сервисов compose.
const DefaultResolver = "127.0.0.11"

// nginxEndpoint — эндпоинт с уже назначенным портом oauth2-proxy и
// именем сертификата. Нулевой порт означает открытый эндпоинт, имя
// сертификата отличается от домена, когда тот закрыт wildcard'ом зоны.
type nginxEndpoint struct {
	Endpoint
	// OAuthPort — процесс, у которого спрашивают про сессию. Ноль
	// означает открытый эндпоинт.
	OAuthPort int
	// ServePort — процесс, чьи служебные адреса (/oauth2/start,
	// /oauth2/callback) живут на этом домене. Ноль — не живут: при общем
	// входе они есть только на auth_domain.
	ServePort int
	// RedirectHeader — значение X-Auth-Request-Redirect: куда вернуть
	// человека после входа. При общем входе адрес полный, иначе хватает
	// пути на том же домене.
	RedirectHeader string
	// LogoutRedirect — куда вернуть после выхода. Всегда корень своего
	// домена: возвращать на страницу, с которой вышли, значит тут же
	// отправить человека логиниться обратно.
	LogoutRedirect string
	// GroupsQuery ограничивает доступ группами на самом подзапросе.
	// Нужен при общем входе, где процесс один на все домены.
	GroupsQuery string
	CertName    string
	// Index различает эндпоинты в именах переменных nginx.
	Index int
}

// UpstreamAuthHeader — готовое значение заголовка Authorization для
// бэкенда; пусто, если реквизитов нет.
func (e nginxEndpoint) UpstreamAuthHeader() string {
	if e.UpstreamAuth == nil {
		return ""
	}
	return e.UpstreamAuth.Header()
}

// AuthVar — переменная nginx с итоговым заголовком авторизации. Своя на
// каждый эндпоинт: реквизиты у бэкендов разные.
func (e nginxEndpoint) AuthVar() string {
	return fmt.Sprintf("$upstream_auth_%d", e.Index)
}

// nginxDefault — заглушка на порт. На одном порту живёт сколько угодно
// доменов, они различаются по SNI; запрос с чужим или отсутствующим
// именем nginx иначе отдал бы первому блоку порта, а с ним и чужой
// сертификат. Сертификат для заглушки всё равно нужен — берётся тот же,
// что у первого домена: до проверки имени дело просто не доходит.
type nginxDefault struct {
	Port     int
	CertName string
}

// nginxDefaults собирает по заглушке на каждый занятый порт в порядке
// появления: конфиг должен получаться одинаковым при одинаковом входе.
func nginxDefaults(endpoints []nginxEndpoint) []nginxDefault {
	var out []nginxDefault
	seen := map[int]bool{}

	for _, e := range endpoints {
		if seen[e.Listen] {
			continue
		}
		seen[e.Listen] = true
		out = append(out, nginxDefault{Port: e.Listen, CertName: e.CertName})
	}
	return out
}

func RenderNginxConfig(w io.Writer, cfg *Config) error {
	resolver := cfg.Resolver
	if resolver == "" {
		resolver = DefaultResolver
	}

	certs := certNames(cfg.Certificates(), cfg.Endpoints)

	// Порты берутся из того же места, что и при запуске процессов, —
	// разъехаться они не могут.
	instances := cfg.OAuthInstances()

	// authPort — процесс, у которого спрашивают про сессию; serve —
	// домены, на которых живут его служебные адреса.
	authPort := map[string]int{}
	serve := map[string]int{}
	groups := map[string]string{}

	shared := len(instances) > 0 && instances[0].Shared
	if shared {
		port := instances[0].Port

		// Начать вход можно с любого закрытого домена — /oauth2/start
		// нужен на каждом. Завершается вход всегда на auth_domain:
		// туда указывает единственный redirect URI в GitLab.
		serve[instances[0].Endpoint.Domain] = port

		for _, e := range cfg.closedEndpoints() {
			authPort[e.Domain] = port
			serve[e.Domain] = port
			groups[e.Domain] = e.AllowedGroupsQuery()
		}
	} else {
		for _, inst := range instances {
			authPort[inst.Endpoint.Domain] = inst.Port
			serve[inst.Endpoint.Domain] = inst.Port
		}
	}

	endpoints := make([]nginxEndpoint, 0, len(cfg.Endpoints))
	for i, e := range cfg.Endpoints {
		ne := nginxEndpoint{
			Endpoint:    e,
			OAuthPort:   authPort[e.Domain],
			ServePort:   serve[e.Domain],
			GroupsQuery: groups[e.Domain],
			CertName:    certs[e.Domain],
			Index:       i,
		}
		if ne.ServePort != 0 {
			// Абсолютный адрес нужен только при общем входе — и только он
			// там и работает; в обычном режиме whitelist-domain не задан,
			// и oauth2-proxy такой возврат отбросил бы.
			ne.RedirectHeader, ne.LogoutRedirect = "$request_uri", "/"
			if shared {
				ne.RedirectHeader = e.ExternalBase() + "$request_uri"
				ne.LogoutRedirect = e.ExternalBase() + "/"
			}
		}
		endpoints = append(endpoints, ne)
	}

	err := nginxTmpl.Execute(w, struct {
		Endpoints []nginxEndpoint
		Defaults  []nginxDefault
		CertDir   string
		Resolver  string
	}{
		Endpoints: endpoints,
		Defaults:  nginxDefaults(endpoints),
		CertDir:   cfg.CertDir,
		Resolver:  resolver,
	})
	if err != nil {
		return fmt.Errorf("рендер конфига nginx: %w", err)
	}
	return nil
}

// Nginx управляет настоящим процессом nginx.
type Nginx struct {
	configPath string
}

func NewNginx(configPath string) *Nginx {
	return &Nginx{configPath: configPath}
}

func (n *Nginx) WriteConfig(cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(n.configPath), 0o755); err != nil {
		return fmt.Errorf("каталог конфига nginx: %w", err)
	}

	f, err := os.CreateTemp(filepath.Dir(n.configPath), ".nginx-*.conf")
	if err != nil {
		return fmt.Errorf("временный конфиг nginx: %w", err)
	}
	tmpName := f.Name()

	defer os.Remove(tmpName)

	if err := RenderNginxConfig(f, cfg); err != nil {
		f.Close()
		return err
	}
	// 0600: в конфиге может лежать пароль к бэкенду, а читает его
	// master-процесс nginx, работающий от root.
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return fmt.Errorf("права на временный конфиг: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("закрытие временного конфига: %w", err)
	}
	if err := os.Rename(tmpName, n.configPath); err != nil {
		return fmt.Errorf("замена конфига nginx: %w", err)
	}
	return nil
}

// Start запускает nginx в основном режиме. Процесс живёт, пока жив агент:
// агент выступает init-процессом контейнера.
//
// В возвращённый канал уходит причина завершения nginx. Сам nginx его не
// перезапускает: конфиг мог стать негодным, и перезапуск в цикле только
// скрыл бы это. Останавливается агент, а поднимает обоих заново docker.
func (n *Nginx) Start(ctx context.Context) (<-chan error, error) {
	cmd := exec.CommandContext(ctx, "nginx", "-c", n.configPath, "-g", "daemon off;")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("запуск nginx: %w", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
		close(done)
	}()

	return done, nil
}

func (n *Nginx) Reload() error {
	out, err := exec.Command("nginx", "-c", n.configPath, "-s", "reload").CombinedOutput()
	if err != nil {
		return fmt.Errorf("перезагрузка nginx: %w: %s", err, out)
	}
	return nil
}
