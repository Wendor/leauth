package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"leauth/internal/api"
	"leauth/internal/server/acmedns"
	"leauth/internal/server/store"
)

func newStatusFixture(t *testing.T) (*http.ServeMux, *store.Store) {
	t.Helper()

	c, _ := store.NewCipher("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	st, err := store.Open(filepath.Join(t.TempDir(), "status.db"), c)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	mux := http.NewServeMux()
	NewStatusPage(st, "admin", "пароль").Register(mux)

	return mux, st
}

func TestStatusRequiresAuth(t *testing.T) {
	mux, _ := newStatusFixture(t)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("код = %d, ожидался 401", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("WWW-Authenticate"), "Basic") {
		t.Error("нет заголовка WWW-Authenticate")
	}
}

func TestStatusRejectsWrongPassword(t *testing.T) {
	mux, _ := newStatusFixture(t)

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "не тот пароль")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("код = %d, ожидался 401", rec.Code)
	}
}

func TestStatusShowsDomains(t *testing.T) {
	mux, st := newStatusFixture(t)
	ctx := context.Background()

	if _, err := st.CreateDomain(ctx, "new.example.com", false, acmedns.Account{
		FullDomain: "acct-new.acme.leauth.ru", SubDomain: "acct-new",
	}); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}

	active, _ := st.CreateDomain(ctx, "old.example.com", true, acmedns.Account{
		FullDomain: "acct-old.acme.leauth.ru", SubDomain: "acct-old",
	})
	st.SaveCert(ctx, active.ID, store.Cert{
		Serial: "0a1b", FullChain: "c", PrivateKey: "k",
		NotAfter: time.Now().Add(60 * 24 * time.Hour),
	})
	st.SetStatus(ctx, active.ID, api.StatusActive, "", 0, time.Time{})

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "пароль")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("код = %d", rec.Code)
	}

	body := rec.Body.String()
	for _, want := range []string{
		"new.example.com",
		"_acme-challenge.new.example.com",
		"acct-new.acme.leauth.ru",
		"pending_cname",
		"old.example.com",
		"active",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("на странице нет %q", want)
		}
	}
}

func TestStatusEscapesLastError(t *testing.T) {
	mux, st := newStatusFixture(t)
	ctx := context.Background()

	d, _ := st.CreateDomain(ctx, "bad.example.com", false, acmedns.Account{FullDomain: "x.acme.leauth.ru"})
	st.SetStatus(ctx, d.ID, api.StatusError, `<script>alert(1)</script>`, 1, time.Now().Add(time.Hour))

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "пароль")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "<script>alert(1)</script>") {
		t.Error("текст ошибки попал на страницу без экранирования")
	}
}

// Страница показывает заголовки о вошедшем в том виде, в каком их
// получает бэкенд: и имя заголовка, и значение.
func TestStatusShowsAuthHeaders(t *testing.T) {
	st := newTestStore(t)
	page := NewStatusPage(st, "admin", "пароль")

	mux := http.NewServeMux()
	page.Register(mux)

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "пароль")
	req.Header.Set("X-Auth-Request-User", "ivanov")
	req.Header.Set("X-Auth-Request-Email", "ivanov@example.com")
	req.Header.Set("X-Auth-Request-Groups", "company/dev/core, company/dev/monitoring/admins")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("код = %d", rec.Code)
	}

	body := rec.Body.String()
	for _, want := range []string{
		"X-Auth-Request-User", "ivanov",
		"X-Auth-Request-Email", "ivanov@example.com",
		"X-Auth-Request-Groups", "company/dev/core, company/dev/monitoring/admins",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("на странице нет %q", want)
		}
	}

	// Заголовки — шапка: они идут до заголовка страницы, а не между ним
	// и таблицей доменов.
	if strings.Index(body, "X-Auth-Request-User") > strings.Index(body, "Состояние доменов") {
		t.Error("блок с заголовками вклинился между заголовком страницы и таблицей")
	}
}

// Без заголовков блок не рисуется: центр открывают и напрямую, минуя прокси.
func TestStatusWithoutAuthHeaders(t *testing.T) {
	page := NewStatusPage(newTestStore(t), "admin", "пароль")

	mux := http.NewServeMux()
	page.Register(mux)

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "пароль")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "X-Auth-Request-") {
		t.Error("блок о вошедшем нарисован без единого заголовка")
	}
}

// Заголовки — это разметка страницы, поэтому их значения экранируются.
func TestStatusEscapesAuthHeaders(t *testing.T) {
	page := NewStatusPage(newTestStore(t), "admin", "пароль")

	mux := http.NewServeMux()
	page.Register(mux)

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "пароль")
	req.Header.Set("X-Auth-Request-User", "<script>alert(1)</script>")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "<script>alert(1)</script>") {
		t.Error("значение заголовка попало в страницу без экранирования")
	}
}

// Набор заголовков задаётся конфигом прокси, поэтому показываются все
// с этим префиксом: известные в привычном порядке, остальные следом.
func TestAuthHeadersOrder(t *testing.T) {
	h := http.Header{}
	h.Set("X-Auth-Request-Groups", "core")
	h.Set("X-Auth-Request-User", "ivanov")
	h.Set("X-Auth-Request-Preferred-Username", "ваня")
	h.Set("X-Forwarded-For", "10.0.0.1")

	got := authHeaders(h)

	want := []authHeader{
		{"X-Auth-Request-User", "ivanov"},
		{"X-Auth-Request-Groups", "core"},
		{"X-Auth-Request-Preferred-Username", "ваня"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("заголовки = %+v, ожидались %+v", got, want)
	}
}
