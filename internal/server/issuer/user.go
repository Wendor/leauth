package issuer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/go-acme/lego/v4/registration"

	"leauth/internal/server/store"
)

// AccountStore — часть хранилища, нужная для ACME-аккаунта.
type AccountStore interface {
	LoadACMEAccount(ctx context.Context) (*store.ACMEAccount, error)
	SaveACMEAccount(ctx context.Context, a store.ACMEAccount) error
}

// acmeUser реализует registration.User из lego.
type acmeUser struct {
	email string
	key   crypto.PrivateKey
	reg   *registration.Resource
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.reg }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// loadOrCreateUser достаёт ключ ACME-аккаунта из хранилища,
// а при первом запуске создаёт его и сохраняет.
func loadOrCreateUser(ctx context.Context, as AccountStore, email string) (*acmeUser, error) {
	acct, err := as.LoadACMEAccount(ctx)
	switch {
	case err == nil:
		key, err := decodeECKey(acct.PrivateKeyPEM)
		if err != nil {
			return nil, err
		}

		u := &acmeUser{email: acct.Email, key: key}
		if len(acct.RegistrationJSON) > 0 {
			var reg registration.Resource
			if err := json.Unmarshal(acct.RegistrationJSON, &reg); err != nil {
				return nil, fmt.Errorf("разбор регистрации ACME: %w", err)
			}
			u.reg = &reg
		}
		return u, nil

	case errors.Is(err, store.ErrNotFound):
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("генерация ключа ACME-аккаунта: %w", err)
		}

		pemKey, err := encodeECKey(key)
		if err != nil {
			return nil, err
		}
		if err := as.SaveACMEAccount(ctx, store.ACMEAccount{Email: email, PrivateKeyPEM: pemKey}); err != nil {
			return nil, err
		}
		return &acmeUser{email: email, key: key}, nil

	default:
		return nil, fmt.Errorf("чтение ACME-аккаунта: %w", err)
	}
}

func encodeECKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("сериализация ключа: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func decodeECKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ключ ACME-аккаунта не является PEM")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("разбор ключа ACME-аккаунта: %w", err)
	}
	return key, nil
}

func mustECKey(u *acmeUser) *ecdsa.PrivateKey {
	return u.key.(*ecdsa.PrivateKey)
}
