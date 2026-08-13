package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"leauth/internal/api"
	"leauth/internal/server/acmedns"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()

	c, err := NewCipher(testKeyHex)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	s, err := Open(filepath.Join(t.TempDir(), "test.db"), c)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	return s
}

func testAccount() acmedns.Account {
	return acmedns.Account{
		Username:   "user-1",
		Password:   "secret",
		FullDomain: "abc.acme.example.org",
		SubDomain:  "abc",
	}
}

func TestCreateAndGetDomain(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.CreateDomain(ctx, "foo.example.com", true, testAccount())
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	if created.ID == 0 {
		t.Error("не проставлен ID")
	}
	if created.Status != api.StatusPendingCNAME {
		t.Errorf("начальный статус = %q, ожидался pending_cname", created.Status)
	}

	got, err := s.GetDomain(ctx, "foo.example.com")
	if err != nil {
		t.Fatalf("GetDomain: %v", err)
	}
	if !got.Wildcard {
		t.Error("потерян флаг wildcard")
	}
	if got.Account.Password != "secret" {
		t.Errorf("пароль acme-dns = %q, ожидался secret", got.Account.Password)
	}
	if got.Account.FullDomain != "abc.acme.example.org" {
		t.Errorf("fulldomain = %q", got.Account.FullDomain)
	}
}

func TestGetDomainMissing(t *testing.T) {
	s := newTestStore(t)

	_, err := s.GetDomain(context.Background(), "нет.example.com")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("ошибка = %v, ожидалась ErrNotFound", err)
	}
}

func TestCreateDomainRejectsDuplicate(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.CreateDomain(ctx, "foo.example.com", false, testAccount()); err != nil {
		t.Fatalf("первое создание: %v", err)
	}
	if _, err := s.CreateDomain(ctx, "foo.example.com", false, testAccount()); err == nil {
		t.Fatal("повторное создание домена должно быть ошибкой")
	}
}

func TestPasswordStoredEncrypted(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.CreateDomain(ctx, "foo.example.com", false, testAccount()); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}

	var blob []byte
	row := s.db.QueryRowContext(ctx, `SELECT acmedns_password_enc FROM domains WHERE name = ?`, "foo.example.com")
	if err := row.Scan(&blob); err != nil {
		t.Fatalf("чтение сырого поля: %v", err)
	}
	if string(blob) == "secret" {
		t.Error("пароль acme-dns лежит в БД открытым текстом")
	}
}

func TestAccountForUsableAsLookup(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.CreateDomain(ctx, "foo.example.com", false, testAccount()); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}

	var lookup acmedns.AccountLookup = s.AccountFor

	acct, err := lookup(ctx, "foo.example.com")
	if err != nil {
		t.Fatalf("AccountFor: %v", err)
	}
	if acct.SubDomain != "abc" {
		t.Errorf("subdomain = %q", acct.SubDomain)
	}
}

func TestSetStatus(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	d, _ := s.CreateDomain(ctx, "foo.example.com", false, testAccount())
	retry := time.Now().Add(10 * time.Minute).Truncate(time.Second)

	if err := s.SetStatus(ctx, d.ID, api.StatusError, "валидация не прошла", 3, retry); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	got, _ := s.GetDomain(ctx, "foo.example.com")
	if got.Status != api.StatusError {
		t.Errorf("статус = %q", got.Status)
	}
	if got.LastError != "валидация не прошла" {
		t.Errorf("last_error = %q", got.LastError)
	}
	if got.FailCount != 3 {
		t.Errorf("fail_count = %d", got.FailCount)
	}
	if !got.RetryAfter.Equal(retry) {
		t.Errorf("retry_after = %v, ожидалось %v", got.RetryAfter, retry)
	}
}

func TestSaveAndLoadCert(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	d, _ := s.CreateDomain(ctx, "foo.example.com", false, testAccount())
	notAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)

	cert := Cert{
		Serial:     "0a1b2c",
		FullChain:  "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
		PrivateKey: "-----BEGIN EC PRIVATE KEY-----\nfake\n-----END EC PRIVATE KEY-----\n",
		NotAfter:   notAfter,
	}
	if err := s.SaveCert(ctx, d.ID, cert); err != nil {
		t.Fatalf("SaveCert: %v", err)
	}

	got, err := s.LatestCert(ctx, d.ID)
	if err != nil {
		t.Fatalf("LatestCert: %v", err)
	}
	if got.Serial != "0a1b2c" {
		t.Errorf("serial = %q", got.Serial)
	}
	if got.PrivateKey != cert.PrivateKey {
		t.Error("приватный ключ не совпадает после расшифровки")
	}
	if !got.NotAfter.Equal(notAfter) {
		t.Errorf("not_after = %v, ожидалось %v", got.NotAfter, notAfter)
	}
}

func TestLatestCertReturnsNewest(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	d, _ := s.CreateDomain(ctx, "foo.example.com", false, testAccount())

	old := Cert{Serial: "old", FullChain: "c", PrivateKey: "k", NotAfter: time.Now().Add(24 * time.Hour)}
	fresh := Cert{Serial: "fresh", FullChain: "c", PrivateKey: "k", NotAfter: time.Now().Add(90 * 24 * time.Hour)}

	if err := s.SaveCert(ctx, d.ID, old); err != nil {
		t.Fatalf("SaveCert old: %v", err)
	}
	if err := s.SaveCert(ctx, d.ID, fresh); err != nil {
		t.Fatalf("SaveCert fresh: %v", err)
	}

	got, _ := s.LatestCert(ctx, d.ID)
	if got.Serial != "fresh" {
		t.Errorf("serial = %q, ожидался fresh", got.Serial)
	}
}

func TestLatestCertMissing(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	d, _ := s.CreateDomain(ctx, "foo.example.com", false, testAccount())

	if _, err := s.LatestCert(ctx, d.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ошибка = %v, ожидалась ErrNotFound", err)
	}
}

func TestSetClientDomainsIsIdempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	s.CreateDomain(ctx, "foo.example.com", false, testAccount())

	for range 2 {
		if err := s.SetClientDomains(ctx, "srv-01", []string{"foo.example.com"}); err != nil {
			t.Fatalf("SetClientDomains: %v", err)
		}
	}

	mine, err := s.DomainsForClient(ctx, "srv-01")
	if err != nil {
		t.Fatalf("DomainsForClient: %v", err)
	}
	if len(mine) != 1 || mine[0] != "foo.example.com" {
		t.Errorf("домены клиента = %v", mine)
	}

	other, err := s.DomainsForClient(ctx, "srv-02")
	if err != nil {
		t.Fatalf("DomainsForClient: %v", err)
	}
	if len(other) != 0 {
		t.Errorf("посторонний клиент не должен иметь доменов: %v", other)
	}
}

// Отзыв убирает и токен, и обслуживание: скомпрометированный прокси
// не должен ни пройти проверку, ни удерживать домены от снятия.
func TestDeleteClientRemovesTokenAndDomains(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	s.CreateDomain(ctx, "foo.example.com", false, testAccount())

	if err := s.SaveClient(ctx, "srv-01", "хеш-токена"); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	if err := s.SetClientDomains(ctx, "srv-01", []string{"foo.example.com"}); err != nil {
		t.Fatalf("SetClientDomains: %v", err)
	}

	if err := s.DeleteClient(ctx, "srv-01"); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}

	if _, err := s.ClientByTokenHash(ctx, "хеш-токена"); !errors.Is(err, ErrNotFound) {
		t.Errorf("токен отозванного прокси всё ещё действует: %v", err)
	}

	mine, _ := s.DomainsForClient(ctx, "srv-01")
	if len(mine) != 0 {
		t.Errorf("за отозванным прокси остались домены: %v", mine)
	}

	// Домен и его учётка acme-dns переживают отзыв: иначе возврат
	// потребовал бы нового CNAME.
	if _, err := s.GetDomain(ctx, "foo.example.com"); err != nil {
		t.Errorf("домен должен сохраниться: %v", err)
	}

	if err := s.DeleteClient(ctx, "srv-01"); !errors.Is(err, ErrNotFound) {
		t.Errorf("повторный отзыв должен сообщать, что прокси нет: %v", err)
	}
}

func TestACMEAccountRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.LoadACMEAccount(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("на пустой БД ожидалась ErrNotFound, получено %v", err)
	}

	acct := ACMEAccount{
		Email:            "admin@example.com",
		PrivateKeyPEM:    []byte("-----BEGIN EC PRIVATE KEY-----"),
		RegistrationJSON: []byte(`{"uri":"https://acme/acct/1"}`),
	}
	if err := s.SaveACMEAccount(ctx, acct); err != nil {
		t.Fatalf("SaveACMEAccount: %v", err)
	}

	got, err := s.LoadACMEAccount(ctx)
	if err != nil {
		t.Fatalf("LoadACMEAccount: %v", err)
	}
	if got.Email != acct.Email {
		t.Errorf("email = %q", got.Email)
	}
	if string(got.PrivateKeyPEM) != string(acct.PrivateKeyPEM) {
		t.Error("ключ ACME-аккаунта не совпадает после расшифровки")
	}
	if string(got.RegistrationJSON) != string(acct.RegistrationJSON) {
		t.Error("регистрация не совпадает")
	}
}

// При первом запуске регистрации в ACME ещё нет: аккаунт создаётся
// раньше, чем lego сходит в Let's Encrypt.
func TestACMEAccountWithoutRegistration(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	err := s.SaveACMEAccount(ctx, ACMEAccount{
		Email:         "admin@example.com",
		PrivateKeyPEM: []byte("-----BEGIN EC PRIVATE KEY-----"),
	})
	if err != nil {
		t.Fatalf("SaveACMEAccount без регистрации: %v", err)
	}

	got, err := s.LoadACMEAccount(ctx)
	if err != nil {
		t.Fatalf("LoadACMEAccount: %v", err)
	}
	if len(got.RegistrationJSON) != 0 {
		t.Errorf("registration = %q, ожидалась пустая", got.RegistrationJSON)
	}
}

func TestListDomains(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	s.CreateDomain(ctx, "a.example.com", false, testAccount())
	s.CreateDomain(ctx, "b.example.com", false, testAccount())

	list, err := s.ListDomains(ctx)
	if err != nil {
		t.Fatalf("ListDomains: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("доменов: %d, ожидалось 2", len(list))
	}
}
