package issuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/registration"

	"leauth/internal/server/store"
)

type memAccountStore struct {
	acct *store.ACMEAccount
}

func (m *memAccountStore) LoadACMEAccount(ctx context.Context) (*store.ACMEAccount, error) {
	if m.acct == nil {
		return nil, store.ErrNotFound
	}
	return m.acct, nil
}

func (m *memAccountStore) SaveACMEAccount(ctx context.Context, a store.ACMEAccount) error {
	m.acct = &a
	return nil
}

func TestUserImplementsLegoInterface(t *testing.T) {
	var _ registration.User = (*acmeUser)(nil)
}

func TestLoadOrCreateUserGeneratesAndPersistsKey(t *testing.T) {
	as := &memAccountStore{}
	ctx := context.Background()

	u1, err := loadOrCreateUser(ctx, as, "admin@example.com")
	if err != nil {
		t.Fatalf("первый вызов: %v", err)
	}
	if as.acct == nil {
		t.Fatal("ключ аккаунта не сохранён в хранилище")
	}
	if u1.GetEmail() != "admin@example.com" {
		t.Errorf("email = %q", u1.GetEmail())
	}

	u2, err := loadOrCreateUser(ctx, as, "admin@example.com")
	if err != nil {
		t.Fatalf("второй вызов: %v", err)
	}

	k1 := u1.GetPrivateKey().(*ecdsa.PrivateKey)
	k2 := u2.GetPrivateKey().(*ecdsa.PrivateKey)
	if !k1.Equal(k2) {
		t.Error("при повторном запуске сгенерирован новый ключ аккаунта")
	}
}

func TestParseCertInfo(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}

	notAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x0a1b2c),
		Subject:      pkix.Name{CommonName: "foo.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("сертификат: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	serial, gotNotAfter, err := ParseCertInfo(pemBytes)
	if err != nil {
		t.Fatalf("ParseCertInfo: %v", err)
	}
	if serial != "a1b2c" {
		t.Errorf("serial = %q, ожидался a1b2c", serial)
	}
	if !gotNotAfter.Equal(notAfter.UTC()) {
		t.Errorf("not_after = %v, ожидалось %v", gotNotAfter, notAfter.UTC())
	}
}

func TestParseCertInfoRejectsGarbage(t *testing.T) {
	if _, _, err := ParseCertInfo([]byte("не сертификат")); err == nil {
		t.Fatal("ожидалась ошибка на мусоре вместо PEM")
	}
}

func TestNewRejectsEmptyDirectory(t *testing.T) {
	_, err := New(context.Background(), Config{Email: "a@b.c"}, nil, &memAccountStore{})
	if err == nil {
		t.Fatal("ожидалась ошибка при пустом адресе ACME-директории")
	}
	if errors.Is(err, store.ErrNotFound) {
		t.Error("ошибка не должна быть ErrNotFound")
	}
}
