//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"leauth/internal/api"
)

const (
	centerURL      = "http://127.0.0.1:8080"
	enrollToken    = "e2e-токен-приёма"
	proxyAddr      = "127.0.0.1:8443"
	pebbleMgmtAddr = "127.0.0.1:15000"
)

// e2eToken — персональный токен теста. Тест представляется центру так
// же, как это делает прокси, и дальше опрашивает состояние своим токеном.
var e2eToken string

// TestEndToEnd поднимает всю цепочку: агент заявляет домен центру,
// человек (в лице теста) прописывает CNAME, центр выпускает сертификат
// в pebble, агент забирает его и перезагружает nginx.
func TestEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	token, err := api.Enroll(ctx, centerURL, enrollToken, "e2e-test")
	if err != nil {
		t.Fatalf("центр не принял тест: %v", err)
	}
	e2eToken = token

	// Агент уже заявил домен при старте контейнера — ждём, пока
	// центр отдаст выданный поддомен acme-dns.
	target := waitForCNAMETarget(ctx, t)
	t.Logf("центр ждёт CNAME на %s", target)

	// «Прописываем CNAME»: стаб начинает отвечать на _acme-challenge.
	startDNSStub(t, stubAddr, "_acme-challenge."+testDomain, target, acmeDNSAddr)

	waitForStatus(ctx, t, api.StatusActive)

	client := proxyClient(t)

	// Агент опрашивает центр раз в 5 секунд: даём ему забрать сертификат.
	var resp *http.Response
	for {
		resp, err = client.Get("https://" + testDomain + ":8443/")
		if err == nil {
			break
		}

		select {
		case <-ctx.Done():
			t.Fatalf("прокси так и не отдал доверенный сертификат: %v", err)
		case <-time.After(2 * time.Second):
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("чтение ответа: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("код = %d, тело: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "Hostname:") {
		t.Errorf("прокси отдал не ответ бэкенда: %s", body)
	}
}

// proxyClient доверяет только CA, которым pebble подписывает выпускаемые
// сертификаты, и направляет все соединения на локальный порт прокси,
// сохраняя SNI.
//
// Это не тот же CA, что в pebble.minica.pem: тем подписан HTTPS-интерфейс
// самого pebble. Корень выпуска генерируется при каждом старте и доступен
// только через management-порт.
func proxyClient(t *testing.T) *http.Client {
	t.Helper()

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(fetchPebbleRoot(t)) {
		t.Fatal("не удалось разобрать корень выпуска pebble")
	}

	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, proxyAddr)
			},
		},
	}
}

// fetchPebbleRoot забирает корневой сертификат, которым pebble подписывает
// выпускаемые сертификаты, с его management-порта.
func fetchPebbleRoot(t *testing.T) []byte {
	t.Helper()

	minica, err := os.ReadFile("pebble.minica.pem")
	if err != nil {
		t.Fatalf("сертификат HTTPS-интерфейса pebble: %v", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(minica) {
		t.Fatal("не удалось разобрать pebble.minica.pem")
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, pebbleMgmtAddr)
			},
		},
	}

	resp, err := client.Get("https://localhost:15000/roots/0")
	if err != nil {
		t.Fatalf("запрос корня pebble: %v", err)
	}
	defer resp.Body.Close()

	root, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("чтение корня pebble: %v", err)
	}
	return root
}

// getDomain спрашивает состояние домена той же ручкой, что и агент.
// Набор сертификатов совпадает с тем, что заявляет агент, поэтому
// опрос из теста не снимает домен с обслуживания.
func getDomain(ctx context.Context, t *testing.T) *api.DomainResponse {
	t.Helper()

	body, err := json.Marshal(api.SyncRequest{
		Certificates: []api.SyncCertificate{{Domain: testDomain}},
	})
	if err != nil {
		t.Fatalf("сериализация запроса: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		centerURL+"/api/v1/sync", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("запрос: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+e2eToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var out api.SyncResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || len(out.Domains) == 0 {
		return nil
	}
	return &out.Domains[0].DomainResponse
}

func waitForCNAMETarget(ctx context.Context, t *testing.T) string {
	t.Helper()

	for {
		if d := getDomain(ctx, t); d != nil && d.CNAME.Target != "" {
			return d.CNAME.Target
		}

		select {
		case <-ctx.Done():
			t.Fatal("центр так и не завёл домен — проверьте логи агента и центра")
		case <-time.After(2 * time.Second):
		}
	}
}

func waitForStatus(ctx context.Context, t *testing.T, want api.DomainStatus) {
	t.Helper()

	var last string

	for {
		if d := getDomain(ctx, t); d != nil {
			if d.Status == want {
				return
			}
			last = string(d.Status) + " / " + d.LastError
		}

		select {
		case <-ctx.Done():
			t.Fatalf("домен не дошёл до статуса %s, последнее состояние: %s", want, last)
		case <-time.After(2 * time.Second):
		}
	}
}
