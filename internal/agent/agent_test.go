package agent

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"leauth/internal/api"
)

type fakeNginx struct {
	mu      sync.Mutex
	writes  int
	starts  int
	reloads int
	// stopped изображает завершение nginx: тест закрывает канал и ждёт,
	// что агент это заметит.
	stopped chan error
}

func (f *fakeNginx) WriteConfig(cfg *Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.writes++
	return nil
}

func (f *fakeNginx) Start(ctx context.Context) (<-chan error, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.starts++
	if f.stopped == nil {
		f.stopped = make(chan error, 1)
	}
	return f.stopped, nil
}

func (f *fakeNginx) Reload() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.reloads++
	return nil
}

func (f *fakeNginx) counts() (int, int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.writes, f.starts, f.reloads
}

// centerStub изображает центр: отвечает на sync заданным состоянием и,
// если серийники разошлись, прикладывает сертификат.
type centerStub struct {
	mu       sync.Mutex
	serial   string
	chainPEM string
	keyPEM   string
	status   api.DomainStatus
	certHits int
	// asked — сертификаты, которые прокси заявил последним запросом.
	asked []api.SyncCertificate
	// enrolled — имена, под которыми прокси представлялся центру.
	enrolled []string
}

func (c *centerStub) handler(t *testing.T) http.Handler {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer токен-приёма" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(api.ErrorResponse{Error: "неверный токен приёма"})
			return
		}

		var req api.EnrollRequest
		json.NewDecoder(r.Body).Decode(&req)

		c.mu.Lock()
		c.enrolled = append(c.enrolled, req.Name)
		c.mu.Unlock()

		json.NewEncoder(w).Encode(api.EnrollResponse{Name: req.Name, Token: "токен-1"})
	})

	mux.HandleFunc("POST /api/v1/sync", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer токен-1" {
			t.Errorf("агент не отправил токен: %q", r.Header.Get("Authorization"))
		}

		var req api.SyncRequest
		json.NewDecoder(r.Body).Decode(&req)

		c.mu.Lock()
		defer c.mu.Unlock()

		c.asked = req.Certificates

		resp := api.SyncResponse{}
		for _, want := range req.Certificates {
			item := api.SyncDomain{DomainResponse: api.DomainResponse{
				Domain:   want.Domain,
				Wildcard: want.Wildcard,
				Status:   c.status,
				Serial:   c.serial,
				CNAME: api.CNAMERecord{
					Name:   "_acme-challenge." + want.Domain,
					Target: "acct.acme.leauth.ru",
				},
			}}

			if c.serial != "" && c.serial != want.Serial {
				c.certHits++
				item.Cert = &api.CertResponse{
					Domain:     want.Domain,
					FullChain:  c.chainPEM,
					PrivateKey: c.keyPEM,
					Serial:     c.serial,
					NotAfter:   time.Now().Add(90 * 24 * time.Hour),
				}
			}

			resp.Domains = append(resp.Domains, item)
		}

		json.NewEncoder(w).Encode(resp)
	})

	return mux
}

// serialOf возвращает серийный номер сертификата в том же виде,
// в каком его отдаёт центр.
func serialOf(t *testing.T, chainPEM []byte) string {
	t.Helper()

	block, _ := pem.Decode(chainPEM)
	if block == nil {
		t.Fatal("цепочка не разбирается как PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("разбор сертификата: %v", err)
	}
	return cert.SerialNumber.Text(16)
}

func newAgentFixture(t *testing.T) (*Agent, *fakeNginx, *centerStub) {
	t.Helper()

	center := &centerStub{status: api.StatusPendingCNAME}
	srv := httptest.NewServer(center.handler(t))
	t.Cleanup(srv.Close)

	cfg := &Config{
		Server:       srv.URL,
		Name:         "srv-01",
		EnrollToken:  "токен-приёма",
		CertDir:      t.TempDir(),
		PollInterval: Duration(time.Hour),
		Endpoints: []Endpoint{
			{Domain: "foo.example.com", Listen: 8443, Upstream: "http://app:3000"},
		},
	}

	nginx := &fakeNginx{}

	a, err := New(cfg, nginx)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a, nginx, center
}

func TestBootstrapCreatesStubsAndStartsNginx(t *testing.T) {
	a, nginx, _ := newAgentFixture(t)

	if err := a.Bootstrap(context.Background()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	if !a.certs.Usable("foo.example.com") {
		t.Error("заглушка не создана — nginx не поднимется")
	}

	writes, starts, _ := nginx.counts()
	if writes != 1 {
		t.Errorf("записей конфига: %d, ожидалась 1", writes)
	}
	if starts != 1 {
		t.Errorf("запусков nginx: %d, ожидался 1", starts)
	}
}

func TestBootstrapKeepsExistingCert(t *testing.T) {
	a, _, _ := newAgentFixture(t)

	chain, key, _ := GenerateSelfSigned("foo.example.com")
	if err := a.certs.Write("foo.example.com", chain, key); err != nil {
		t.Fatalf("подготовка: %v", err)
	}

	before := a.certs.Serial("foo.example.com")

	if err := a.Bootstrap(context.Background()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	after := a.certs.Serial("foo.example.com")
	if before != after {
		t.Error("существующий сертификат заменён заглушкой")
	}
}

func TestSyncSkipsWhenCertNotIssued(t *testing.T) {
	a, nginx, _ := newAgentFixture(t)

	if err := a.Bootstrap(context.Background()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	a.Sync(context.Background())

	_, _, reloads := nginx.counts()
	if reloads != 0 {
		t.Errorf("перезагрузок: %d — сертификата ещё нет, перезагружать нечего", reloads)
	}
}

func TestSyncDownloadsAndReloads(t *testing.T) {
	a, nginx, center := newAgentFixture(t)
	ctx := context.Background()

	if err := a.Bootstrap(ctx); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	chain, key, _ := GenerateSelfSigned("foo.example.com")

	// Центр отдаёт серийник того же сертификата, что лежит в цепочке —
	// именно по нему агент понимает, что скачивать нечего.
	center.mu.Lock()
	center.chainPEM = string(chain)
	center.keyPEM = string(key)
	center.serial = serialOf(t, chain)
	center.status = api.StatusActive
	center.mu.Unlock()

	a.Sync(ctx)

	_, _, reloads := nginx.counts()
	if reloads != 1 {
		t.Fatalf("перезагрузок: %d, ожидалась 1", reloads)
	}

	// Повторный проход ничего не меняет: серийники совпали.
	a.Sync(ctx)

	_, _, reloads = nginx.counts()
	if reloads != 1 {
		t.Errorf("перезагрузок после второго прохода: %d — лишняя перезагрузка", reloads)
	}

	center.mu.Lock()
	hits := center.certHits
	center.mu.Unlock()

	if hits != 1 {
		t.Errorf("скачиваний сертификата: %d, ожидалось 1", hits)
	}
}

func TestSyncSurvivesCenterOutage(t *testing.T) {
	a, nginx, _ := newAgentFixture(t)
	ctx := context.Background()

	if err := a.Bootstrap(ctx); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	// Центр «пропал»: адрес заведомо недоступен.
	a.client = api.NewClient("http://127.0.0.1:1", "токен-1")

	a.Sync(ctx)

	_, _, reloads := nginx.counts()
	if reloads != 0 {
		t.Error("перезагрузка при недоступном центре не нужна")
	}
}

// Прокси заявляет центру сертификаты, а не эндпоинты: два поддомена
// одной зоны — это один сертификат и один CNAME.
func TestSyncAsksForZoneCertificateOnce(t *testing.T) {
	a, _, center := newAgentFixture(t)
	ctx := context.Background()

	a.cfg.WildcardZones = []string{"example.com"}
	a.cfg.Endpoints = []Endpoint{
		{Domain: "docs.example.com", Listen: 8443, Upstream: "http://docs:80"},
		{Domain: "wiki.example.com", Listen: 8444, Upstream: "http://wiki:80"},
	}

	if err := a.Bootstrap(ctx); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	a.Sync(ctx)

	center.mu.Lock()
	asked := center.asked
	center.mu.Unlock()

	if len(asked) != 1 {
		t.Fatalf("заявлено сертификатов: %d, ожидался 1: %+v", len(asked), asked)
	}
	if asked[0].Domain != "example.com" || !asked[0].Wildcard {
		t.Errorf("заявлен сертификат %+v, ожидался wildcard на зону", asked[0])
	}
}

// Серийник заглушки уходит центру наравне с настоящим: иначе центр не
// поймёт, что настоящий сертификат прокси ещё не получил.
func TestSyncReportsLocalSerial(t *testing.T) {
	a, _, center := newAgentFixture(t)
	ctx := context.Background()

	if err := a.Bootstrap(ctx); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	local := a.certs.Serial("foo.example.com")

	a.Sync(ctx)

	center.mu.Lock()
	asked := center.asked
	center.mu.Unlock()

	if len(asked) != 1 || asked[0].Serial != local {
		t.Errorf("заявлено %+v, ожидался серийник заглушки %q", asked, local)
	}
}

// При первом запуске прокси меняет общий токен приёма на персональный
// и сохраняет его: добавление прокси не требует действий на центре.
func TestSyncEnrollsOnFirstRun(t *testing.T) {
	a, _, center := newAgentFixture(t)
	ctx := context.Background()

	if err := a.Bootstrap(ctx); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	a.Sync(ctx)

	center.mu.Lock()
	enrolled := center.enrolled
	center.mu.Unlock()

	if len(enrolled) != 1 || enrolled[0] != "srv-01" {
		t.Fatalf("центру представились как %v", enrolled)
	}

	saved, err := readToken(a.tokenPath())
	if err != nil {
		t.Fatalf("readToken: %v", err)
	}
	if saved != "токен-1" {
		t.Errorf("сохранённый токен = %q", saved)
	}
}

// Повторный приём не нужен: токен уже лежит в томе.
func TestSyncReusesSavedToken(t *testing.T) {
	a, _, center := newAgentFixture(t)
	ctx := context.Background()

	if err := a.Bootstrap(ctx); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	a.Sync(ctx)

	// Новый агент на том же томе: центр про него уже знает.
	restarted, err := New(a.cfg, &fakeNginx{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	restarted.Sync(ctx)

	center.mu.Lock()
	enrolled := center.enrolled
	center.mu.Unlock()

	if len(enrolled) != 1 {
		t.Errorf("приёмов: %d, ожидался 1 — токен должен переживать перезапуск", len(enrolled))
	}
}

// Без токена приёма и без сохранённого токена прокси не падает:
// он продолжает отвечать на заглушке и жалуется в лог.
func TestSyncWithoutAnyTokenKeepsRunning(t *testing.T) {
	a, nginx, _ := newAgentFixture(t)
	ctx := context.Background()

	a.cfg.EnrollToken = ""

	if err := a.Bootstrap(ctx); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	a.Sync(ctx)

	_, starts, reloads := nginx.counts()
	if starts != 1 {
		t.Errorf("запусков nginx: %d — прокси должен подняться на заглушке", starts)
	}
	if reloads != 0 {
		t.Errorf("перезагрузок: %d", reloads)
	}
}

// Пока домен живёт на заглушке, прокси спрашивает центр раз в минуту:
// иначе выпущенный сертификат ждал бы конца часа.
func TestPollDelaySpeedsUpWhileWaiting(t *testing.T) {
	dir := t.TempDir()

	cfg := &Config{
		Server:       "https://leauth.example.com",
		Name:         "srv-01",
		CertDir:      dir,
		PollInterval: Duration(time.Hour),
		Endpoints: []Endpoint{
			{Domain: "foo.example.com", Listen: 8443, Upstream: "http://app:3000"},
		},
	}

	a, err := New(cfg, &fakeNginx{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Сертификата нет вовсе.
	if got := a.pollDelay(); got != WaitingInterval {
		t.Errorf("без сертификата пауза = %v, ожидалась %v", got, WaitingInterval)
	}

	// Заглушка — то же самое.
	certPEM, keyPEM, err := GenerateSelfSigned("foo.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.certs.Write("foo.example.com", certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if got := a.pollDelay(); got != WaitingInterval {
		t.Errorf("с заглушкой пауза = %v, ожидалась %v", got, WaitingInterval)
	}

	// Настоящий сертификат возвращает обычный интервал.
	caPEM, leafPEM, leafKeyPEM := issueSignedCert(t, "foo.example.com")
	if err := a.certs.Write("foo.example.com", append(leafPEM, caPEM...), leafKeyPEM); err != nil {
		t.Fatal(err)
	}
	if got := a.pollDelay(); got != time.Hour {
		t.Errorf("с выпущенным сертификатом пауза = %v, ожидался час", got)
	}
}

// Интервал короче минуты остаётся как задан: ускорять уже некуда.
func TestPollDelayKeepsShortInterval(t *testing.T) {
	cfg := &Config{
		Server:       "https://leauth.example.com",
		Name:         "srv-01",
		CertDir:      t.TempDir(),
		PollInterval: Duration(5 * time.Second),
		Endpoints: []Endpoint{
			{Domain: "foo.example.com", Listen: 8443, Upstream: "http://app:3000"},
		},
	}

	a, err := New(cfg, &fakeNginx{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := a.pollDelay(); got != 5*time.Second {
		t.Errorf("пауза = %v, ожидались 5s", got)
	}
}

// Битый сертификат на диске не должен останавливать агента: раньше он
// уходил в бесконечный перезапуск, потому что заглушка не пересоздавалась,
// а разбор файла падал на каждом круге.
func TestBootstrapReplacesCorruptedCert(t *testing.T) {
	a, _, _ := newAgentFixture(t)

	fullchain, key := a.certs.Paths("foo.example.com")
	if err := os.MkdirAll(filepath.Dir(fullchain), 0o755); err != nil {
		t.Fatalf("подготовка: %v", err)
	}
	// Обрезанный файл — то, что остаётся после сбоя питания.
	for _, p := range []string{fullchain, key} {
		if err := os.WriteFile(p, []byte("-----BEGIN CERT"), 0o600); err != nil {
			t.Fatalf("подготовка: %v", err)
		}
	}

	if err := a.Bootstrap(context.Background()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	if !a.certs.Usable("foo.example.com") {
		t.Fatal("битая пара не заменена — nginx не поднимется")
	}
	// Пустой серийник заставит центр прислать сертификат целиком.
	if serial := a.certs.Serial("foo.example.com"); serial == "" {
		t.Error("после замены серийник должен читаться")
	}
}

// Прокси без nginx ничего не обслуживает, поэтому агент обязан завершиться
// и дать docker поднять контейнер заново.
func TestRunStopsWhenNginxDies(t *testing.T) {
	a, nginx, _ := newAgentFixture(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	// Ждём, пока агент поднимет nginx, и «роняем» процесс.
	for {
		if _, starts, _ := nginx.counts(); starts > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	nginx.mu.Lock()
	stopped := nginx.stopped
	nginx.mu.Unlock()
	stopped <- errors.New("exit status 1")

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("падение nginx должно останавливать агента с ошибкой")
		}
		if !strings.Contains(err.Error(), "nginx") {
			t.Errorf("ошибка = %v — из неё не видно причину", err)
		}
	case <-ctx.Done():
		t.Fatal("агент продолжил работу без nginx")
	}
}
