package api

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDomainResponseJSONNames(t *testing.T) {
	notAfter := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	resp := DomainResponse{
		Domain: "foo.example.com",
		Status: StatusPendingCNAME,
		CNAME: CNAMERecord{
			Name:   "_acme-challenge.foo.example.com",
			Target: "abc.acme.leauth.ru",
		},
		Serial:   "0a1b",
		NotAfter: &notAfter,
	}

	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, key := range []string{"domain", "status", "cname", "serial", "not_after"} {
		if _, ok := got[key]; !ok {
			t.Errorf("в JSON нет поля %q: %s", key, b)
		}
	}
	if got["status"] != "pending_cname" {
		t.Errorf("status = %v, ожидалось pending_cname", got["status"])
	}
	if _, ok := got["last_error"]; ok {
		t.Error("пустой last_error не должен попадать в JSON")
	}
}

func TestCertResponseJSONNames(t *testing.T) {
	b, err := json.Marshal(CertResponse{
		Domain:     "foo.example.com",
		FullChain:  "-----BEGIN CERTIFICATE-----",
		PrivateKey: "-----BEGIN EC PRIVATE KEY-----",
		Serial:     "0a1b",
		NotAfter:   time.Now(),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, key := range []string{"domain", "fullchain", "privkey", "serial", "not_after"} {
		if _, ok := got[key]; !ok {
			t.Errorf("в JSON нет поля %q: %s", key, b)
		}
	}
}
