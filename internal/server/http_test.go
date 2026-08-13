package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"leauth/internal/api"
	"leauth/internal/server/acmedns"
	"leauth/internal/server/store"
)

type stubACMEDNS struct {
	n   int
	err error
}

func (s *stubACMEDNS) Register(ctx context.Context) (acmedns.Account, error) {
	if s.err != nil {
		return acmedns.Account{}, s.err
	}

	s.n++
	return acmedns.Account{
		Username:   "user",
		Password:   "pass",
		FullDomain: "acct-1.acme.leauth.ru",
		SubDomain:  "acct-1",
	}, nil
}

func (s *stubACMEDNS) SetTXT(ctx context.Context, acct acmedns.Account, value string) error {
	return nil
}

func newTestAPI(t *testing.T) (*API, *store.Store, *stubACMEDNS) {
	t.Helper()

	st := newTestStore(t)
	ad := &stubACMEDNS{}
	auth := NewAuthenticator(st, "токен-приёма")

	// Два прокси уже приняты: их токены известны тестам.
	ctx := context.Background()
	for name, token := range map[string]string{"srv-01": "token-1", "srv-02": "token-2"} {
		if err := st.SaveClient(ctx, name, HashToken(token)); err != nil {
			t.Fatalf("SaveClient: %v", err)
		}
	}

	return NewAPI(st, ad, auth), st, ad
}

// serves — обслуживает ли прокси домен сейчас.
func serves(t *testing.T, st *store.Store, client, domain string) bool {
	t.Helper()

	mine, err := st.DomainsForClient(context.Background(), client)
	if err != nil {
		t.Fatalf("DomainsForClient: %v", err)
	}
	return slices.Contains(mine, domain)
}

func do(t *testing.T, a *API, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)
	return rec
}

// sync шлёт запрос от имени клиента и разбирает успешный ответ.
func sync(t *testing.T, a *API, token, body string) api.SyncResponse {
	t.Helper()

	rec := do(t, a, "POST", "/api/v1/sync", token, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("код = %d, ожидался 200: %s", rec.Code, rec.Body)
	}

	var resp api.SyncResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("разбор ответа: %v", err)
	}
	return resp
}

func TestSyncCreatesDomain(t *testing.T) {
	a, _, ad := newTestAPI(t)

	resp := sync(t, a, "token-1", `{"certificates":[{"domain":"foo.example.com","wildcard":true}]}`)
	if len(resp.Domains) != 1 {
		t.Fatalf("доменов в ответе: %d", len(resp.Domains))
	}

	d := resp.Domains[0]
	if d.Status != api.StatusPendingCNAME {
		t.Errorf("статус = %q", d.Status)
	}
	if d.CNAME.Name != "_acme-challenge.foo.example.com" {
		t.Errorf("имя CNAME = %q", d.CNAME.Name)
	}
	if d.CNAME.Target != "acct-1.acme.leauth.ru" {
		t.Errorf("цель CNAME = %q", d.CNAME.Target)
	}
	if !d.Wildcard {
		t.Error("потерян флаг wildcard")
	}
	if d.Cert != nil {
		t.Error("сертификата ещё нет, а он приложен")
	}
	if ad.n != 1 {
		t.Errorf("регистраций в acme-dns: %d, ожидалась 1", ad.n)
	}
}

func TestSyncTwiceReusesAccount(t *testing.T) {
	a, st, ad := newTestAPI(t)

	sync(t, a, "token-1", `{"certificates":[{"domain":"foo.example.com"}]}`)
	sync(t, a, "token-2", `{"certificates":[{"domain":"foo.example.com"}]}`)

	if ad.n != 1 {
		t.Errorf("регистраций в acme-dns: %d — аккаунт должен переиспользоваться", ad.n)
	}

	for _, client := range []string{"srv-01", "srv-02"} {
		if !serves(t, st, client, "foo.example.com") {
			t.Errorf("клиент %s должен быть привязан к домену", client)
		}
	}
}

func TestSyncConflictingWildcard(t *testing.T) {
	a, _, _ := newTestAPI(t)

	sync(t, a, "token-1", `{"certificates":[{"domain":"foo.example.com","wildcard":false}]}`)

	rec := do(t, a, "POST", "/api/v1/sync", "token-2", `{"certificates":[{"domain":"foo.example.com","wildcard":true}]}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("код = %d, ожидался 409", rec.Code)
	}
}

func TestSyncValidation(t *testing.T) {
	a, _, _ := newTestAPI(t)

	for _, body := range []string{
		`{"certificates":[{"domain":""}]}`,
		`{"certificates":[{"domain":"*.foo.example.com"}]}`,
		`{"certificates":[{"domain":"без-точки"}]}`,
		`{"certificates":[{"domain":"про бел.example.com"}]}`,
		// Пустой набор снял бы с обслуживания все домены прокси.
		`{"certificates":[]}`,
		`не json`,
	} {
		rec := do(t, a, "POST", "/api/v1/sync", "token-1", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("тело %q дало код %d, ожидался 400", body, rec.Code)
		}
	}
}

func TestUnauthorized(t *testing.T) {
	a, _, _ := newTestAPI(t)

	for _, token := range []string{"", "чужой-токен"} {
		rec := do(t, a, "POST", "/api/v1/sync", token, `{"certificates":[{"domain":"foo.example.com"}]}`)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("токен %q дал код %d, ожидался 401", token, rec.Code)
		}
	}
}

// saveCert кладёт домену сертификат, как это сделал бы планировщик.
func saveCert(t *testing.T, st *store.Store, domain, serial string) time.Time {
	t.Helper()

	ctx := context.Background()

	d, err := st.GetDomain(ctx, domain)
	if err != nil {
		t.Fatalf("GetDomain: %v", err)
	}

	notAfter := time.Now().Add(60 * 24 * time.Hour).Truncate(time.Second)

	err = st.SaveCert(ctx, d.ID, store.Cert{
		Serial:     serial,
		FullChain:  "chain-pem",
		PrivateKey: "key-pem",
		NotAfter:   notAfter,
	})
	if err != nil {
		t.Fatalf("SaveCert: %v", err)
	}
	if err := st.SetStatus(ctx, d.ID, api.StatusActive, "", 0, time.Time{}); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	return notAfter
}

func TestSyncSendsCertWhenSerialDiffers(t *testing.T) {
	a, st, _ := newTestAPI(t)

	sync(t, a, "token-1", `{"certificates":[{"domain":"foo.example.com"}]}`)
	notAfter := saveCert(t, st, "foo.example.com", "0a1b")

	resp := sync(t, a, "token-1", `{"certificates":[{"domain":"foo.example.com","serial":"старый"}]}`)

	d := resp.Domains[0]
	if d.Serial != "0a1b" {
		t.Errorf("serial = %q", d.Serial)
	}
	if d.NotAfter == nil || !d.NotAfter.Equal(notAfter.UTC()) {
		t.Errorf("not_after = %v, ожидалось %v", d.NotAfter, notAfter.UTC())
	}
	if d.Cert == nil {
		t.Fatal("серийники разошлись, а сертификат не приложен")
	}
	if d.Cert.FullChain != "chain-pem" || d.Cert.PrivateKey != "key-pem" {
		t.Errorf("материал сертификата не совпадает: %+v", d.Cert)
	}
}

// Неизменившийся сертификат каждый час гонять незачем.
func TestSyncOmitsCertWhenSerialMatches(t *testing.T) {
	a, st, _ := newTestAPI(t)

	sync(t, a, "token-1", `{"certificates":[{"domain":"foo.example.com"}]}`)
	saveCert(t, st, "foo.example.com", "0a1b")

	resp := sync(t, a, "token-1", `{"certificates":[{"domain":"foo.example.com","serial":"0a1b"}]}`)

	if resp.Domains[0].Cert != nil {
		t.Error("серийники совпадают, а сертификат приложен")
	}
	if resp.Domains[0].Serial != "0a1b" {
		t.Errorf("serial должен приходить всегда, получено %q", resp.Domains[0].Serial)
	}
}

// Домен, пропавший из набора, перестаёт обслуживаться, но не удаляется:
// учётка acme-dns остаётся, и вернуть домен можно без нового CNAME.
func TestSyncDropsMissingDomain(t *testing.T) {
	a, st, ad := newTestAPI(t)
	ctx := context.Background()

	sync(t, a, "token-1", `{"certificates":[{"domain":"a.example.com"},{"domain":"b.example.com"}]}`)
	sync(t, a, "token-1", `{"certificates":[{"domain":"a.example.com"}]}`)

	if serves(t, st, "srv-01", "b.example.com") {
		t.Error("домен вне набора должен быть снят с прокси")
	}

	served, err := st.ListServedDomains(ctx)
	if err != nil {
		t.Fatalf("ListServedDomains: %v", err)
	}
	if len(served) != 1 || served[0].Name != "a.example.com" {
		t.Errorf("обслуживаемые домены = %+v", served)
	}

	if _, err := st.GetDomain(ctx, "b.example.com"); err != nil {
		t.Errorf("домен должен сохраниться вместе с учёткой acme-dns: %v", err)
	}

	// Возврат домена не требует новой регистрации в acme-dns.
	before := ad.n
	sync(t, a, "token-1", `{"certificates":[{"domain":"a.example.com"},{"domain":"b.example.com"}]}`)
	if ad.n != before {
		t.Errorf("регистраций в acme-dns: было %d, стало %d", before, ad.n)
	}
}

// Снятие домена одним прокси не трогает другой.
func TestSyncKeepsDomainClaimedByOtherClient(t *testing.T) {
	a, st, _ := newTestAPI(t)

	sync(t, a, "token-1", `{"certificates":[{"domain":"foo.example.com"}]}`)
	sync(t, a, "token-2", `{"certificates":[{"domain":"foo.example.com"}]}`)
	sync(t, a, "token-1", `{"certificates":[{"domain":"other.example.com"}]}`)

	if !serves(t, st, "srv-02", "foo.example.com") {
		t.Error("домен второго прокси не должен сниматься вместе с первым")
	}
}

// Сбой на одном домене не должен снимать с обслуживания остальные:
// иначе временная недоступность acme-dns останавливала бы продление.
func TestSyncFailureKeepsExistingClaims(t *testing.T) {
	a, st, ad := newTestAPI(t)

	sync(t, a, "token-1", `{"certificates":[{"domain":"a.example.com"}]}`)

	ad.err = errors.New("acme-dns недоступен")

	rec := do(t, a, "POST", "/api/v1/sync", "token-1",
		`{"certificates":[{"domain":"a.example.com"},{"domain":"new.example.com"}]}`)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("код = %d, ожидался 502: %s", rec.Code, rec.Body)
	}

	if !serves(t, st, "srv-01", "a.example.com") {
		t.Error("сбой на новом домене снял с обслуживания рабочий")
	}
}

func TestSyncNormalizesDomainCase(t *testing.T) {
	a, _, _ := newTestAPI(t)

	resp := sync(t, a, "token-1", `{"certificates":[{"domain":"  FOO.Example.COM  "}]}`)
	if resp.Domains[0].Domain != "foo.example.com" {
		t.Errorf("нормализованное имя = %q", resp.Domains[0].Domain)
	}
}

func TestEnrollEndpointIssuesToken(t *testing.T) {
	a, _, _ := newTestAPI(t)

	rec := do(t, a, "POST", "/api/v1/enroll", "токен-приёма", `{"name":"srv-03"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("код = %d: %s", rec.Code, rec.Body)
	}

	var resp api.EnrollResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("разбор ответа: %v", err)
	}
	if resp.Name != "srv-03" || resp.Token == "" {
		t.Fatalf("ответ = %+v", resp)
	}

	// Выданный токен сразу годится для основной ручки.
	sync(t, a, resp.Token, `{"certificates":[{"domain":"foo.example.com"}]}`)
}

func TestEnrollEndpointRejects(t *testing.T) {
	a, _, _ := newTestAPI(t)

	cases := []struct {
		name  string
		token string
		body  string
		want  int
	}{
		{"чужой токен", "не-тот", `{"name":"srv-03"}`, http.StatusUnauthorized},
		{"персональный токен не годится", "token-1", `{"name":"srv-03"}`, http.StatusUnauthorized},
		{"плохое имя", "токен-приёма", `{"name":"srv 03"}`, http.StatusBadRequest},
		{"не json", "токен-приёма", `не json`, http.StatusBadRequest},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			rec := do(t, a, "POST", "/api/v1/enroll", tt.token, tt.body)
			if rec.Code != tt.want {
				t.Errorf("код = %d, ожидался %d: %s", rec.Code, tt.want, rec.Body)
			}
		})
	}
}

// Закрытый приём отвечает 403, а не молча создаёт прокси.
func TestEnrollEndpointClosed(t *testing.T) {
	st := newTestStore(t)
	a := NewAPI(st, &stubACMEDNS{}, NewAuthenticator(st, ""))

	rec := do(t, a, "POST", "/api/v1/enroll", "что-угодно", `{"name":"srv-03"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("код = %d, ожидался 403: %s", rec.Code, rec.Body)
	}
}

// Тело запроса ограничено: без лимита одно соединение заняло бы память
// центра целиком.
func TestRejectsHugeBody(t *testing.T) {
	a, _, _ := newTestAPI(t)

	body := `{"certificates":[{"domain":"foo.example.com","serial":"` +
		strings.Repeat("a", maxRequestBody) + `"}]}`

	rec := do(t, a, "POST", "/api/v1/sync", "token-1", body)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("код = %d, ожидался 413: %s", rec.Code, rec.Body)
	}
}

// Отказ в приёме наступает до разбора тела: аноним не должен заставлять
// центр парсить присланный JSON.
func TestEnrollChecksTokenBeforeBody(t *testing.T) {
	a, _, _ := newTestAPI(t)

	rec := do(t, a, "POST", "/api/v1/enroll", "чужой", "не json вовсе")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("код = %d, ожидался 401: %s", rec.Code, rec.Body)
	}
}

// Детали внутренней ошибки остаются в логе: наружу уходит только код.
func TestWriteInternalHidesDetails(t *testing.T) {
	rec := httptest.NewRecorder()
	writeInternal(rec, "тест", errors.New("sql: no such table: domains"))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("код = %d, ожидался 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "sql") {
		t.Errorf("наружу утекли детали: %s", rec.Body)
	}
}
