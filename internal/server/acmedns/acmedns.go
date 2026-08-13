// Package acmedns — работа с сервером acme-dns: регистрация аккаунтов
// и запись значений TXT для DNS-01.
package acmedns

import (
	"context"
	"fmt"

	"github.com/nrdcg/goacmedns"
)

// Account — учётные данные acme-dns для одного домена.
// FullDomain — то, на что владелец зоны направляет CNAME.
type Account struct {
	Username   string
	Password   string
	FullDomain string
	SubDomain  string
}

// Client — минимум операций acme-dns, нужный центру.
type Client interface {
	Register(ctx context.Context) (Account, error)
	SetTXT(ctx context.Context, acct Account, value string) error
}

type restClient struct {
	c *goacmedns.Client
}

// New создаёт клиента acme-dns. baseURL — адрес его REST API,
// например http://acme-dns:8081.
func New(baseURL string) (Client, error) {
	c, err := goacmedns.NewClient(baseURL)
	if err != nil {
		return nil, fmt.Errorf("клиент acme-dns: %w", err)
	}
	return &restClient{c: c}, nil
}

func (r *restClient) Register(ctx context.Context) (Account, error) {
	acct, err := r.c.RegisterAccount(ctx, nil)
	if err != nil {
		return Account{}, fmt.Errorf("регистрация в acme-dns: %w", err)
	}
	return Account{
		Username:   acct.Username,
		Password:   acct.Password,
		FullDomain: acct.FullDomain,
		SubDomain:  acct.SubDomain,
	}, nil
}

func (r *restClient) SetTXT(ctx context.Context, acct Account, value string) error {
	err := r.c.UpdateTXTRecord(ctx, goacmedns.Account{
		Username:  acct.Username,
		Password:  acct.Password,
		SubDomain: acct.SubDomain,
	}, value)
	if err != nil {
		return fmt.Errorf("запись TXT в acme-dns: %w", err)
	}
	return nil
}
