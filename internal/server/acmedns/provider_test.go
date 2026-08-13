package acmedns

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/go-acme/lego/v4/challenge"
)

type fakeClient struct {
	calls []struct {
		acct  Account
		value string
	}
	err error
}

func (f *fakeClient) Register(ctx context.Context) (Account, error) {
	return Account{}, errors.New("не должно вызываться")
}

func (f *fakeClient) SetTXT(ctx context.Context, acct Account, value string) error {
	if f.err != nil {
		return f.err
	}
	f.calls = append(f.calls, struct {
		acct  Account
		value string
	}{acct, value})
	return nil
}

func TestProviderImplementsLegoInterface(t *testing.T) {
	var _ challenge.Provider = (*Provider)(nil)
}

func TestPresentWritesHashedKeyAuth(t *testing.T) {
	fc := &fakeClient{}
	acct := Account{Username: "u", Password: "p", SubDomain: "abc"}

	p := NewProvider(fc, func(ctx context.Context, domain string) (Account, error) {
		if domain != "example.com" {
			t.Errorf("lookup вызван с %q, ожидался example.com", domain)
		}
		return acct, nil
	})

	if err := p.Present("example.com", "token", "keyauth-1"); err != nil {
		t.Fatalf("Present: %v", err)
	}

	sum := sha256.Sum256([]byte("keyauth-1"))
	want := base64.RawURLEncoding.EncodeToString(sum[:])

	if len(fc.calls) != 1 {
		t.Fatalf("вызовов SetTXT: %d, ожидался 1", len(fc.calls))
	}
	if fc.calls[0].value != want {
		t.Errorf("значение TXT = %q, ожидалось %q", fc.calls[0].value, want)
	}
	if fc.calls[0].acct.SubDomain != "abc" {
		t.Errorf("использован не тот аккаунт: %+v", fc.calls[0].acct)
	}
}

func TestPresentTwiceForWildcardUsesSameAccount(t *testing.T) {
	fc := &fakeClient{}
	acct := Account{Username: "u", SubDomain: "abc"}
	p := NewProvider(fc, func(ctx context.Context, domain string) (Account, error) {
		return acct, nil
	})

	// Сертификат на example.com и *.example.com даёт две авторизации
	// с одним и тем же Identifier.Value и разными keyAuth.
	if err := p.Present("example.com", "t1", "keyauth-base"); err != nil {
		t.Fatalf("Present base: %v", err)
	}
	if err := p.Present("example.com", "t2", "keyauth-wildcard"); err != nil {
		t.Fatalf("Present wildcard: %v", err)
	}

	if len(fc.calls) != 2 {
		t.Fatalf("вызовов SetTXT: %d, ожидалось 2", len(fc.calls))
	}
	if fc.calls[0].value == fc.calls[1].value {
		t.Error("значения TXT совпали, а должны различаться")
	}
}

func TestPresentReturnsLookupError(t *testing.T) {
	p := NewProvider(&fakeClient{}, func(ctx context.Context, domain string) (Account, error) {
		return Account{}, errors.New("нет такого домена")
	})

	if err := p.Present("example.com", "t", "k"); err == nil {
		t.Fatal("ожидалась ошибка поиска аккаунта")
	}
}

func TestCleanUpIsNoop(t *testing.T) {
	fc := &fakeClient{}
	p := NewProvider(fc, func(ctx context.Context, domain string) (Account, error) {
		return Account{}, nil
	})

	if err := p.CleanUp("example.com", "t", "k"); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	if len(fc.calls) != 0 {
		t.Error("CleanUp не должен ходить в acme-dns")
	}
}
