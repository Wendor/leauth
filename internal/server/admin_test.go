package server

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"leauth/internal/api"
	"leauth/internal/server/acmedns"
)

// adminConfig — конфиг, которого хватает разовым командам: они трогают
// только базу.
func adminConfig(t *testing.T) *Config {
	t.Helper()

	return &Config{
		MasterKey:     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		DB:            filepath.Join(t.TempDir(), "admin.db"),
		CheckInterval: 5 * time.Minute,
	}
}

// Отзыв прокси лишает его токен силы и снимает домены, но не трогает сам
// домен: его учётка acme-dns должна пережить отзыв, иначе возврат
// потребовал бы нового CNAME.
func TestRevokeCommand(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)

	st, err := openStore(cfg)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}

	if _, err := st.CreateDomain(ctx, "foo.example.com", false, acmedns.Account{
		Username: "u", Password: "p", FullDomain: "acct.acme.example.com", SubDomain: "acct",
	}); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	if err := st.SaveClient(ctx, "srv-07", HashToken("токен")); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	if err := st.SetClientDomains(ctx, "srv-07", []string{"foo.example.com"}); err != nil {
		t.Fatalf("SetClientDomains: %v", err)
	}
	st.Close()

	if err := Revoke(ctx, cfg, "srv-07"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	st, err = openStore(cfg)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	defer st.Close()

	if _, ok := NewAuthenticator(st, "").ClientFor(ctx, "Bearer токен"); ok {
		t.Error("токен отозванного прокси всё ещё принимается")
	}
	if _, err := st.GetDomain(ctx, "foo.example.com"); err != nil {
		t.Errorf("домен должен пережить отзыв: %v", err)
	}

	if err := Revoke(ctx, cfg, "нет-такого"); err == nil {
		t.Error("отзыв несуществующего прокси должен быть ошибкой")
	}
}

// Перевыпуск снимает домен со статуса active, и планировщик берёт его в
// работу как новый: ключ, унесённый отозванным прокси, иначе действовал
// бы до конца срока сертификата.
func TestRenewCommand(t *testing.T) {
	ctx := context.Background()
	cfg := adminConfig(t)

	st, err := openStore(cfg)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}

	d, err := st.CreateDomain(ctx, "foo.example.com", false, acmedns.Account{
		Username: "u", Password: "p", FullDomain: "acct.acme.example.com", SubDomain: "acct",
	})
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	if err := st.SetStatus(ctx, d.ID, api.StatusActive, "", 0, time.Time{}); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	st.Close()

	// Имя приводится к канону: команду набирает человек.
	if err := Renew(ctx, cfg, "  FOO.Example.COM  "); err != nil {
		t.Fatalf("Renew: %v", err)
	}

	st, err = openStore(cfg)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	defer st.Close()

	got, err := st.GetDomain(ctx, "foo.example.com")
	if err != nil {
		t.Fatalf("GetDomain: %v", err)
	}
	if got.Status == api.StatusActive {
		t.Error("статус остался active — планировщик не станет выпускать заново")
	}
	// Бэкофф от прошлых неудач не должен откладывать перевыпуск.
	if !got.RetryAfter.IsZero() || got.FailCount != 0 {
		t.Errorf("бэкофф не сброшен: retry_after=%v fail_count=%d", got.RetryAfter, got.FailCount)
	}

	if err := Renew(ctx, cfg, "нет.example.com"); err == nil {
		t.Error("перевыпуск несуществующего домена должен быть ошибкой")
	}
	if err := Renew(ctx, cfg, "не домен"); err == nil {
		t.Error("негодное имя должно отвергаться")
	}
}

// Домен, помеченный на перевыпуск, действительно уходит в выпуск на
// ближайшем тике — а не ждёт RENEW_BEFORE, как действующий сертификат.
func TestRenewMakesSchedulerReissue(t *testing.T) {
	sch, st, _, iss := newSchedulerFixture(t)
	ctx := context.Background()

	iss.certPEM = makeCert(t, time.Now().Add(90*24*time.Hour))

	d := addDomain(t, st, "foo.example.com", false)
	sch.Tick(ctx)

	if len(iss.gotNames) != 1 {
		t.Fatalf("вызовов Obtain: %d, ожидался 1", len(iss.gotNames))
	}

	// Сертификат свежий: обычный тик его не трогает.
	sch.Tick(ctx)
	if len(iss.gotNames) != 1 {
		t.Fatalf("свежий сертификат перевыпущен без повода: %d вызовов", len(iss.gotNames))
	}

	if err := st.SetStatus(ctx, d.ID, api.StatusPendingCNAME, "", 0, time.Time{}); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	sch.Tick(ctx)
	if len(iss.gotNames) != 2 {
		t.Errorf("вызовов Obtain: %d — помеченный домен не перевыпущен", len(iss.gotNames))
	}

	got, _ := st.GetDomain(ctx, "foo.example.com")
	if got.Status != api.StatusActive {
		t.Errorf("статус после перевыпуска = %q", got.Status)
	}
}
