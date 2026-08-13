package server

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
	"path/filepath"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certificate"

	"leauth/internal/api"
	"leauth/internal/server/acmedns"
	"leauth/internal/server/precheck"
	"leauth/internal/server/store"
)

// makeCert возвращает самоподписанный сертификат в PEM с заданным сроком.
func makeCert(t *testing.T, notAfter time.Time) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xbeef),
		Subject:      pkix.Name{CommonName: "foo.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("сертификат: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

type fakePrechecker struct {
	err   error
	calls int
}

func (f *fakePrechecker) Verify(ctx context.Context, domain string, acct acmedns.Account) error {
	f.calls++
	return f.err
}

type fakeIssuer struct {
	certPEM  []byte
	err      error
	gotNames [][]string
}

func (f *fakeIssuer) Obtain(domains []string) (*certificate.Resource, error) {
	f.gotNames = append(f.gotNames, domains)
	if f.err != nil {
		return nil, f.err
	}
	return &certificate.Resource{
		Domain:      domains[0],
		Certificate: f.certPEM,
		PrivateKey:  []byte("-----BEGIN EC PRIVATE KEY-----\nkey\n-----END EC PRIVATE KEY-----\n"),
	}, nil
}

func newSchedulerFixture(t *testing.T) (*Scheduler, *store.Store, *fakePrechecker, *fakeIssuer) {
	t.Helper()

	c, err := store.NewCipher("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	st, err := store.Open(filepath.Join(t.TempDir(), "sched.db"), c)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	p := &fakePrechecker{}
	i := &fakeIssuer{}

	return NewScheduler(st, p, i, 30*24*time.Hour, 5*time.Minute), st, p, i
}

func addDomain(t *testing.T, st *store.Store, name string, wildcard bool) *store.Domain {
	t.Helper()

	d, err := st.CreateDomain(context.Background(), name, wildcard, acmedns.Account{
		Username: "u", Password: "p", FullDomain: "acct.acme.leauth.ru", SubDomain: "acct",
	})
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}

	// Планировщик работает только с доменами, которые кто-то обслуживает.
	served, err := st.DomainsForClient(context.Background(), "srv-01")
	if err != nil {
		t.Fatalf("DomainsForClient: %v", err)
	}
	if err := st.SetClientDomains(context.Background(), "srv-01", append(served, name)); err != nil {
		t.Fatalf("SetClientDomains: %v", err)
	}
	return d
}

func TestTickIssuesAfterSuccessfulPrecheck(t *testing.T) {
	sch, st, _, iss := newSchedulerFixture(t)
	ctx := context.Background()

	notAfter := time.Now().Add(90 * 24 * time.Hour)
	iss.certPEM = makeCert(t, notAfter)

	d := addDomain(t, st, "foo.example.com", false)

	sch.Tick(ctx)

	got, err := st.GetDomain(ctx, "foo.example.com")
	if err != nil {
		t.Fatalf("GetDomain: %v", err)
	}
	if got.Status != api.StatusActive {
		t.Fatalf("статус = %q, ожидался active (last_error=%q)", got.Status, got.LastError)
	}

	cert, err := st.LatestCert(ctx, d.ID)
	if err != nil {
		t.Fatalf("LatestCert: %v", err)
	}
	if cert.Serial != "beef" {
		t.Errorf("serial = %q, ожидался beef", cert.Serial)
	}
}

func TestTickPassesWildcardNames(t *testing.T) {
	sch, st, _, iss := newSchedulerFixture(t)
	iss.certPEM = makeCert(t, time.Now().Add(90*24*time.Hour))

	addDomain(t, st, "example.com", true)

	sch.Tick(context.Background())

	if len(iss.gotNames) != 1 {
		t.Fatalf("вызовов Obtain: %d", len(iss.gotNames))
	}
	want := []string{"example.com", "*.example.com"}
	if len(iss.gotNames[0]) != 2 || iss.gotNames[0][0] != want[0] || iss.gotNames[0][1] != want[1] {
		t.Errorf("имена = %v, ожидались %v", iss.gotNames[0], want)
	}
}

func TestTickKeepsPendingWhenCNAMEMissing(t *testing.T) {
	sch, st, pre, iss := newSchedulerFixture(t)
	pre.err = precheck.ErrCNAMENotConfigured

	addDomain(t, st, "foo.example.com", false)

	sch.Tick(context.Background())

	got, _ := st.GetDomain(context.Background(), "foo.example.com")
	if got.Status != api.StatusPendingCNAME {
		t.Errorf("статус = %q, ожидался pending_cname", got.Status)
	}
	if got.FailCount != 0 {
		t.Errorf("fail_count = %d — ожидание CNAME не должно копить неудачи", got.FailCount)
	}
	if !got.RetryAfter.IsZero() {
		t.Error("для ожидания CNAME не должен ставиться бэкофф")
	}
	if len(iss.gotNames) != 0 {
		t.Error("выпуск не должен запускаться без подтверждённого CNAME")
	}
}

func TestTickBackoffGrows(t *testing.T) {
	sch, st, _, iss := newSchedulerFixture(t)
	iss.err = errors.New("Let's Encrypt недоступен")

	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	sch.Now = func() time.Time { return now }

	addDomain(t, st, "foo.example.com", false)
	ctx := context.Background()

	sch.Tick(ctx)

	got, _ := st.GetDomain(ctx, "foo.example.com")
	if got.Status != api.StatusError {
		t.Fatalf("статус = %q, ожидался error", got.Status)
	}
	if got.FailCount != 1 {
		t.Errorf("fail_count = %d", got.FailCount)
	}
	if want := now.Add(5 * time.Minute); !got.RetryAfter.Equal(want) {
		t.Errorf("retry_after = %v, ожидалось %v", got.RetryAfter, want)
	}

	// Второй тик через бэкофф: неудача повторяется, пауза удваивается.
	now = now.Add(5 * time.Minute)
	sch.Tick(ctx)

	got, _ = st.GetDomain(ctx, "foo.example.com")
	if got.FailCount != 2 {
		t.Errorf("fail_count = %d, ожидалось 2", got.FailCount)
	}
	if want := now.Add(10 * time.Minute); !got.RetryAfter.Equal(want) {
		t.Errorf("retry_after = %v, ожидалось %v", got.RetryAfter, want)
	}
}

func TestBackoffCappedAtHour(t *testing.T) {
	if got := backoff(1); got != 5*time.Minute {
		t.Errorf("backoff(1) = %v", got)
	}
	if got := backoff(4); got != 40*time.Minute {
		t.Errorf("backoff(4) = %v", got)
	}
	if got := backoff(10); got != time.Hour {
		t.Errorf("backoff(10) = %v, ожидался потолок в час", got)
	}
}

func TestTickSkipsDuringBackoff(t *testing.T) {
	sch, st, pre, _ := newSchedulerFixture(t)

	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	sch.Now = func() time.Time { return now }

	d := addDomain(t, st, "foo.example.com", false)
	ctx := context.Background()

	st.SetStatus(ctx, d.ID, api.StatusError, "прошлая ошибка", 1, now.Add(5*time.Minute))

	sch.Tick(ctx)

	if pre.calls != 0 {
		t.Error("домен в бэкоффе не должен проверяться")
	}
}

func TestTickRenewsOnlyNearExpiry(t *testing.T) {
	sch, st, _, iss := newSchedulerFixture(t)
	ctx := context.Background()

	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	sch.Now = func() time.Time { return now }

	d := addDomain(t, st, "foo.example.com", false)
	st.SaveCert(ctx, d.ID, store.Cert{
		Serial: "old", FullChain: "c", PrivateKey: "k",
		NotAfter: now.Add(60 * 24 * time.Hour),
	})
	st.SetStatus(ctx, d.ID, api.StatusActive, "", 0, time.Time{})

	sch.Tick(ctx)
	if len(iss.gotNames) != 0 {
		t.Fatal("сертификат со сроком 60 дней обновлять рано")
	}

	// Через 40 дней до истечения остаётся 20 — пора.
	now = now.Add(40 * 24 * time.Hour)
	iss.certPEM = makeCert(t, now.Add(90*24*time.Hour))

	sch.Tick(ctx)
	if len(iss.gotNames) != 1 {
		t.Fatalf("вызовов Obtain: %d, ожидался 1", len(iss.gotNames))
	}
}

// Домен, снятый со всех прокси, продлевать незачем: планировщик обходит
// его стороной, но запись и учётка acme-dns остаются в базе.
func TestTickSkipsUnservedDomain(t *testing.T) {
	sch, st, _, iss := newSchedulerFixture(t)
	ctx := context.Background()

	iss.certPEM = makeCert(t, time.Now().Add(90*24*time.Hour))

	addDomain(t, st, "foo.example.com", false)
	if err := st.SetClientDomains(ctx, "srv-01", nil); err != nil {
		t.Fatalf("SetClientDomains: %v", err)
	}

	sch.Tick(ctx)

	if len(iss.gotNames) != 0 {
		t.Errorf("вызовов Obtain: %d — необслуживаемый домен не должен выпускаться", len(iss.gotNames))
	}
	if _, err := st.GetDomain(ctx, "foo.example.com"); err != nil {
		t.Errorf("домен должен сохраниться в базе: %v", err)
	}
}
