package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSyncSendsTokenAndBody(t *testing.T) {
	var gotAuth, gotPath string
	var gotBody SyncRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&gotBody)

		json.NewEncoder(w).Encode(SyncResponse{Domains: []SyncDomain{{
			DomainResponse: DomainResponse{
				Domain: "foo.example.com",
				Status: StatusPendingCNAME,
				CNAME:  CNAMERecord{Name: "_acme-challenge.foo.example.com", Target: "acct.acme.leauth.ru"},
			},
		}}})
	}))
	defer srv.Close()

	resp, err := NewClient(srv.URL, "токен-1").Sync(context.Background(), []SyncCertificate{
		{Domain: "foo.example.com", Wildcard: true, Serial: "0a1b"},
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}

	if gotAuth != "Bearer токен-1" {
		t.Errorf("заголовок авторизации = %q", gotAuth)
	}
	if gotPath != "/api/v1/sync" {
		t.Errorf("путь = %q", gotPath)
	}
	if len(gotBody.Certificates) != 1 {
		t.Fatalf("тело запроса = %+v", gotBody)
	}
	if c := gotBody.Certificates[0]; c.Domain != "foo.example.com" || !c.Wildcard || c.Serial != "0a1b" {
		t.Errorf("сертификат в запросе = %+v", c)
	}
	if resp.Domains[0].CNAME.Target != "acct.acme.leauth.ru" {
		t.Errorf("ответ разобран неверно: %+v", resp.Domains[0])
	}
}

// Сертификат приходит вложенным в состояние домена, а не отдельным запросом.
func TestSyncParsesInlineCert(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(SyncResponse{Domains: []SyncDomain{{
			DomainResponse: DomainResponse{Domain: "foo.example.com", Status: StatusActive, Serial: "0a1b"},
			Cert: &CertResponse{
				Domain:     "foo.example.com",
				FullChain:  "chain",
				PrivateKey: "key",
				Serial:     "0a1b",
			},
		}}})
	}))
	defer srv.Close()

	resp, err := NewClient(srv.URL, "t").Sync(context.Background(), []SyncCertificate{{Domain: "foo.example.com"}})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}

	d := resp.Domains[0]
	if d.Serial != "0a1b" {
		t.Errorf("поля состояния не разобраны: %+v", d)
	}
	if d.Cert == nil || d.Cert.FullChain != "chain" || d.Cert.PrivateKey != "key" {
		t.Errorf("материал разобран неверно: %+v", d.Cert)
	}
}

func TestClientReportsServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "требуется корректный Bearer-токен"})
	}))
	defer srv.Close()

	_, err := NewClient(srv.URL, "плохой").Sync(context.Background(), []SyncCertificate{{Domain: "foo.example.com"}})
	if err == nil {
		t.Fatal("ожидалась ошибка")
	}
	if !strings.Contains(err.Error(), "требуется корректный Bearer-токен") {
		t.Errorf("сообщение центра потеряно: %v", err)
	}
}
