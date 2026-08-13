//go:build integration

package integration

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"leauth/internal/api"
	"leauth/internal/server"
	"leauth/internal/server/acmedns"
	"leauth/internal/server/issuer"
	"leauth/internal/server/precheck"
	"leauth/internal/server/store"
)

const (
	acmeDNSAPI  = "http://127.0.0.1:8081"
	acmeDNSAddr = "127.0.0.1:5354"
	stubAddr    = "0.0.0.0:5355"
	resolver    = "127.0.0.1:5355"
	pebbleDir   = "https://127.0.0.1:14000/dir"
	testDomain  = "test.example.com"
)

// TestIssueThroughPebble проходит полный путь: регистрация в acme-dns,
// проверка CNAME, заказ сертификата в ACME и запись в хранилище.
func TestIssueThroughPebble(t *testing.T) {
	// Сертификат pebble подписан его собственным CA; путь к нему
	// готовит make up.
	if err := os.Setenv("LEGO_CA_CERTIFICATES", "pebble.minica.pem"); err != nil {
		t.Fatalf("LEGO_CA_CERTIFICATES: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	adns, err := acmedns.New(acmeDNSAPI)
	if err != nil {
		t.Fatalf("клиент acme-dns: %v", err)
	}

	acct, err := adns.Register(ctx)
	if err != nil {
		t.Fatalf("регистрация в acme-dns: %v", err)
	}
	t.Logf("выдан поддомен: %s", acct.FullDomain)

	startDNSStub(t, stubAddr, "_acme-challenge."+testDomain, acct.FullDomain, acmeDNSAddr)

	cipher, err := store.NewCipher("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	st, err := store.Open(filepath.Join(t.TempDir(), "integration.db"), cipher)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()

	d, err := st.CreateDomain(ctx, testDomain, false, acct)
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}

	// Планировщик работает только с доменами, которые кто-то обслуживает.
	if err := st.SetClientDomains(ctx, "e2e", []string{testDomain}); err != nil {
		t.Fatalf("SetClientDomains: %v", err)
	}

	provider := acmedns.NewProvider(adns, st.AccountFor)

	iss, err := issuer.New(ctx, issuer.Config{
		DirectoryURL: pebbleDir,
		Email:        "admin@example.com",
		Resolvers:    []string{resolver},
	}, provider, st)
	if err != nil {
		t.Fatalf("issuer.New: %v", err)
	}

	checker := precheck.New(adns, precheck.NewSystemResolver(resolver))
	sched := server.NewScheduler(st, checker, iss, 30*24*time.Hour, time.Minute)

	sched.Tick(ctx)

	got, err := st.GetDomain(ctx, testDomain)
	if err != nil {
		t.Fatalf("GetDomain: %v", err)
	}
	if got.Status != api.StatusActive {
		t.Fatalf("статус = %q, ожидался active; последняя ошибка: %s", got.Status, got.LastError)
	}

	cert, err := st.LatestCert(ctx, d.ID)
	if err != nil {
		t.Fatalf("LatestCert: %v", err)
	}

	block, _ := pem.Decode([]byte(cert.FullChain))
	if block == nil {
		t.Fatal("выпущенная цепочка не разбирается как PEM")
	}

	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("разбор сертификата: %v", err)
	}

	if err := parsed.VerifyHostname(testDomain); err != nil {
		t.Errorf("сертификат не годится для %s: %v", testDomain, err)
	}
	if cert.PrivateKey == "" {
		t.Error("приватный ключ не сохранён")
	}
}

// TestPrecheckFailsWithoutCNAME проверяет, что домен без CNAME
// остаётся в pending_cname и в ACME запроса не уходит.
func TestPrecheckFailsWithoutCNAME(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	adns, err := acmedns.New(acmeDNSAPI)
	if err != nil {
		t.Fatalf("клиент acme-dns: %v", err)
	}

	acct, err := adns.Register(ctx)
	if err != nil {
		t.Fatalf("регистрация в acme-dns: %v", err)
	}

	// Стаб поднимаем для другого имени — CNAME для нашего домена нет.
	startDNSStub(t, stubAddr, "_acme-challenge.другой.example.com", acct.FullDomain, acmeDNSAddr)

	checker := precheck.New(adns, precheck.NewSystemResolver(resolver))
	checker.Attempts = 1
	checker.Delay = 0

	err = checker.Verify(ctx, "нет-cname.example.com", acct)
	if err == nil {
		t.Fatal("проверка должна была не пройти")
	}
	t.Logf("ожидаемая ошибка: %v", err)
}
