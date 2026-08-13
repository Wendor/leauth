package acmedns

import (
	"context"
	"fmt"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
)

// AccountLookup возвращает учётные данные acme-dns для домена.
// Реализуется хранилищем центра.
type AccountLookup func(ctx context.Context, domain string) (Account, error)

// DefaultPropagationTimeout — сколько ждать, пока запись увидят
// резолверы. Минуты по умолчанию мало: публичный резолвер кеширует
// SERVFAIL на несколько минут, если авторитативный сервер моргнул, и
// вся попытка сгорает впустую — следующая будет только через backoff
// планировщика.
const DefaultPropagationTimeout = 5 * time.Minute

// Provider решает DNS-01, записывая значение TXT через acme-dns.
// Реализует challenge.Provider из lego.
type Provider struct {
	client  Client
	lookup  AccountLookup
	timeout time.Duration
}

func NewProvider(c Client, lookup AccountLookup) *Provider {
	return &Provider{client: c, lookup: lookup, timeout: DefaultPropagationTimeout}
}

// SetTimeout меняет ожидание распространения. Ноль возвращает значение
// по умолчанию.
func (p *Provider) SetTimeout(d time.Duration) {
	if d <= 0 {
		d = DefaultPropagationTimeout
	}
	p.timeout = d
}

// Timeout реализует challenge.ProviderTimeout: без него lego берёт свою
// минуту и об этой настройке не спрашивает.
func (p *Provider) Timeout() (timeout, interval time.Duration) {
	return p.timeout, dns01.DefaultPollingInterval
}

// Present записывает значение challenge в acme-dns.
//
// lego передаёт сюда authz.Identifier.Value — имя без префикса "*.",
// поэтому для wildcard-заказа домен приходит базовым и аккаунт находится
// тот же самый. Для сертификата с базовым доменом и wildcard метод
// вызывается дважды с разными keyAuth; acme-dns хранит два последних
// значения на аккаунт, чего для этого случая достаточно.
func (p *Provider) Present(domain, token, keyAuth string) error {
	ctx := context.Background()

	acct, err := p.lookup(ctx, domain)
	if err != nil {
		return fmt.Errorf("аккаунт acme-dns для %s: %w", domain, err)
	}

	info := dns01.GetChallengeInfo(domain, keyAuth)

	if err := p.client.SetTXT(ctx, acct, info.Value); err != nil {
		return fmt.Errorf("запись challenge для %s: %w", domain, err)
	}
	return nil
}

// CleanUp ничего не делает: значения TXT в acme-dns перезаписываются
// при следующем выпуске, а удалять их нечем — API acme-dns такой
// операции не предоставляет.
func (p *Provider) CleanUp(domain, token, keyAuth string) error {
	return nil
}
