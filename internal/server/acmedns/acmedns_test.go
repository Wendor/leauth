package acmedns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegisterParsesResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/register" {
			t.Errorf("путь = %q, ожидался /register", r.URL.Path)
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"username":   "user-1",
			"password":   "secret",
			"fulldomain": "abc.acme.example.org",
			"subdomain":  "abc",
			"allowfrom":  []string{},
		})
	}))
	defer srv.Close()

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	acct, err := c.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if acct.Username != "user-1" || acct.Password != "secret" {
		t.Errorf("учётные данные разобраны неверно: %+v", acct)
	}
	if acct.FullDomain != "abc.acme.example.org" || acct.SubDomain != "abc" {
		t.Errorf("домены разобраны неверно: %+v", acct)
	}
}

func TestSetTXTSendsCredentialsAndValue(t *testing.T) {
	var gotUser, gotKey string
	var gotBody map[string]string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/update" {
			t.Errorf("путь = %q, ожидался /update", r.URL.Path)
		}
		gotUser = r.Header.Get("X-Api-User")
		gotKey = r.Header.Get("X-Api-Key")
		json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(map[string]string{"txt": gotBody["txt"]})
	}))
	defer srv.Close()

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	acct := Account{Username: "user-1", Password: "secret", SubDomain: "abc"}
	if err := c.SetTXT(context.Background(), acct, "value-43-chars"); err != nil {
		t.Fatalf("SetTXT: %v", err)
	}

	if gotUser != "user-1" || gotKey != "secret" {
		t.Errorf("заголовки авторизации: user=%q key=%q", gotUser, gotKey)
	}
	if gotBody["subdomain"] != "abc" {
		t.Errorf("subdomain = %q", gotBody["subdomain"])
	}
	if gotBody["txt"] != "value-43-chars" {
		t.Errorf("txt = %q", gotBody["txt"])
	}
}
