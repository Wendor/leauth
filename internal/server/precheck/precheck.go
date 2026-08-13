// Package precheck проверяет, что владелец домена прописал CNAME
// на выданный ему поддомен acme-dns.
package precheck

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"leauth/internal/server/acmedns"
)

// ErrCNAMENotConfigured — значение TXT в acme-dns не видно по
// _acme-challenge.<домен>. Обычно означает, что CNAME ещё не прописан.
var ErrCNAMENotConfigured = errors.New("CNAME не настроен или ещё не распространился")

type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	// LookupCNAME возвращает конечное имя цепочки CNAME. Нужен для
	// дешёвой проверки перед пробой: домен, ждущий человека, не должен
	// каждые пять минут писать в acme-dns значение, которое никто
	// не прочитает.
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// NewSystemResolver возвращает резолвер, который ходит в указанный сервер,
// например "1.1.1.1:53". Локальный резолвер контейнера не годится:
// он может отдавать внутреннюю зону вместо публичной.
func NewSystemResolver(addr string) Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, network, addr)
		},
	}
}

// NewSystemResolvers — по резолверу на каждый заданный адрес.
func NewSystemResolvers(addrs []string) []Resolver {
	out := make([]Resolver, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, NewSystemResolver(a))
	}
	return out
}

type Checker struct {
	client acmedns.Client
	// res — резолверы по кругу: недоступность одного не должна
	// останавливать выпуск, ради этого их и настраивают несколько.
	res []Resolver

	// Attempts и Delay задают повторы: публичный резолвер может ответить
	// из кэша раньше, чем acme-dns отдаст новое значение.
	Attempts int
	Delay    time.Duration
}

// New принимает резолверы в порядке предпочтения. Попытки идут по кругу,
// поэтому при трёх попытках и двух резолверах второй тоже будет опрошен.
func New(c acmedns.Client, resolvers ...Resolver) *Checker {
	return &Checker{client: c, res: resolvers, Attempts: 3, Delay: 2 * time.Second}
}

// Verify записывает случайное значение в acme-dns и убеждается, что оно
// видно по _acme-challenge.<domain>.
func (c *Checker) Verify(ctx context.Context, domain string, acct acmedns.Account) error {
	if len(c.res) == 0 {
		return errors.New("не задан ни один резолвер для проверки CNAME")
	}

	name := "_acme-challenge." + domain

	// Домен, ждущий человека, отсеивается одним дешёвым запросом: писать
	// ради него пробу в acme-dns каждые пять минут незачем, а ждать
	// повторов LookupTXT — тем более.
	if target, known := c.cname(ctx, name); known && !sameName(target, acct.FullDomain) {
		if target == "" {
			return fmt.Errorf("%w: записи %s в зоне нет, нужен CNAME на %s",
				ErrCNAMENotConfigured, name, acct.FullDomain)
		}
		return fmt.Errorf("%w: %s указывает на %q вместо %q",
			ErrCNAMENotConfigured, name, target, acct.FullDomain)
	}

	probe, err := randomProbe()
	if err != nil {
		return err
	}

	if err := c.client.SetTXT(ctx, acct, probe); err != nil {
		return fmt.Errorf("проба в acme-dns: %w", err)
	}

	// Попыток не меньше, чем резолверов: иначе настроенный запасной
	// резолвер не был бы опрошен ни разу.
	attempts := max(c.Attempts, len(c.res))

	var lastErr error
	for attempt := range attempts {
		if attempt > 0 && c.Delay > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(c.Delay):
			}
		}

		values, err := c.res[attempt%len(c.res)].LookupTXT(ctx, name)
		if err != nil {
			lastErr = err
			continue
		}

		if slices.Contains(values, probe) {
			return nil
		}
		lastErr = nil
	}

	if lastErr != nil {
		return fmt.Errorf("%w: запрос %s не удался: %v", ErrCNAMENotConfigured, name, lastErr)
	}
	return fmt.Errorf("%w: пробное значение не видно по %s", ErrCNAMENotConfigured, name)
}

// cname возвращает конечное имя цепочки CNAME для name. Второй результат
// говорит, получен ли содержательный ответ; пустое имя при known=true
// означает, что записи в зоне нет.
//
// Различать «записи нет» и «резолвер не ответил» здесь обязательно:
// именно первое — самый частый случай ожидания, и ради него вся проверка
// и делается. NXDOMAIN на _acme-challenge.<домен> означает, что CNAME
// ещё не прописан: своих адресных записей у этого имени не бывает.
//
// Резолверы опрашиваются по очереди до первого ответа: сбой одного
// не должен решать за все.
func (c *Checker) cname(ctx context.Context, name string) (string, bool) {
	for _, r := range c.res {
		target, err := r.LookupCNAME(ctx, name)
		if err == nil && target != "" {
			return target, true
		}

		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return "", true
		}
	}
	return "", false
}

// sameName сравнивает доменные имена: регистр и завершающая точка
// в ответе резолвера значения не имеют.
func sameName(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

// randomProbe возвращает строку той же формы и длины, что и значение
// challenge у Let's Encrypt: 43 символа base64url.
func randomProbe() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("генерация пробного значения: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
