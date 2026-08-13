//go:build integration

package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"leauth/internal/agent"
)

// Проверки этого файла отвечают на вопрос, на который не отвечает ни
// сравнение строк в шаблоне, ни nginx -t: что в итоге доезжает до
// бэкенда. Все дыры с подделкой заголовков находились в проде именно
// потому, что проверять это было нечем.

// hostAddr — адрес хоста изнутри контейнера. Бэкенд и заглушка
// oauth2-proxy живут в самом тесте, как и в остальных тестах пакета.
//
// Берётся именно IP, а не host.docker.internal: nginx резолвит апстримы
// через директиву resolver и /etc/hosts не читает, поэтому имя, добавленное
// через --add-host, ему ничего не даёт.
func hostAddr(t *testing.T) string {
	t.Helper()

	// Адрес спрашивается у самого docker: на Linux шлюзом служит адрес
	// бриджа, а на Docker Desktop хост стоит за виртуальной машиной, и
	// её шлюз ведёт не туда.
	out, err := exec.Command("docker", "run", "--rm",
		"--add-host", "host.docker.internal:host-gateway",
		nginxImage, "getent", "hosts", "host.docker.internal").CombinedOutput()
	if err != nil {
		t.Fatalf("адрес хоста изнутри контейнера: %v\n%s", err, out)
	}

	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		t.Fatalf("docker не сообщил адрес хоста: %s", out)
	}
	return fields[0]
}

// upstreamTo — адрес сервиса, поднятого тестом на хосте.
func upstreamTo(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	return fmt.Sprintf("http://%s:%d", hostAddr(t), portOf(t, srv))
}

// echoServer отдаёт заголовки запроса обратно и умеет отвечать потоком.
type echoServer struct {
	*httptest.Server
	port int
}

// startEcho поднимает бэкенд на всех адресах: из контейнера до 127.0.0.1
// не достучаться.
func startEcho(t *testing.T) *echoServer {
	t.Helper()

	mux := http.NewServeMux()

	// /headers — что именно получил бэкенд.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"headers": r.Header,
			"path":    r.URL.RequestURI(),
		})
	})

	// /stream — поток, который не заканчивается сразу. С буферизацией
	// nginx придержал бы первую часть до конца ответа.
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		fmt.Fprint(w, "data: первая\n\n")
		w.(http.Flusher).Flush()

		select {
		case <-time.After(3 * time.Second):
		case <-r.Context().Done():
		}
		fmt.Fprint(w, "data: вторая\n\n")
	})

	return &echoServer{Server: startOnAllAddrs(t, mux)}
}

// startOnAllAddrs — httptest.Server, слушающий 0.0.0.0.
func startOnAllAddrs(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()

	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("слушатель: %v", err)
	}

	srv := httptest.NewUnstartedServer(h)
	srv.Listener.Close()
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)

	return srv
}

func portOf(t *testing.T, srv *httptest.Server) int {
	t.Helper()

	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("порт: %v", err)
	}

	var n int
	fmt.Sscanf(port, "%d", &n)
	return n
}

// oauthStub изображает oauth2-proxy: отвечает на подзапрос проверки
// сессии и на служебные адреса входа.
type oauthStub struct {
	*httptest.Server
	// authorized — пускать ли; когда false, подзапрос отвечает 401 и
	// nginx уводит на вход.
	authorized bool
	// lastAuthQuery — строка запроса последнего подзапроса: по ней видно,
	// передал ли nginx ограничение по группам.
	lastAuthQuery string
}

func startOAuthStub(t *testing.T) *oauthStub {
	t.Helper()

	stub := &oauthStub{authorized: true}

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/auth", func(w http.ResponseWriter, r *http.Request) {
		stub.lastAuthQuery = r.URL.RawQuery

		if !stub.authorized {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Ровно то, что отдаёт oauth2-proxy при --set-xauthrequest.
		w.Header().Set("X-Auth-Request-User", "настоящий-пользователь")
		w.Header().Set("X-Auth-Request-Email", "real@example.com")
		w.Header().Set("X-Auth-Request-Groups", "platform/sre")
		w.Header().Set("X-Auth-Request-Preferred-Username", "настоящий-ник")
		w.WriteHeader(http.StatusAccepted)
	})
	mux.HandleFunc("/oauth2/", func(w http.ResponseWriter, r *http.Request) {
		// Вход: сюда nginx приводит неавторизованного.
		w.Header().Set("X-Stub-Redirect", r.Header.Get("X-Auth-Request-Redirect"))
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "вход")
	})

	stub.Server = startOnAllAddrs(t, mux)
	return stub
}

// runNginx поднимает nginx с этим конфигом и возвращает клиент,
// ходящий на него по HTTPS.
//
// Адреса заглушек подставляются заменой в готовом конфиге: шаблон
// намеренно прибивает oauth2-proxy к 127.0.0.1, а внутри контейнера это
// сам контейнер. Проверяем мы устройство location'ов, а не адрес.
func runNginx(t *testing.T, cfg *agent.Config, oauthPort int) *http.Client {
	t.Helper()

	cfg.Server = "https://leauth.example.com"
	cfg.Name = "srv-01"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("конфиг не прошёл валидацию агента: %v", err)
	}

	dir := prepareNginx(t, cfg)

	path := filepath.Join(dir, "nginx.conf")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("чтение конфига: %v", err)
	}

	conf := strings.ReplaceAll(string(raw),
		fmt.Sprintf("127.0.0.1:%d", agent.OAuthBasePort),
		fmt.Sprintf("%s:%d", hostAddr(t), oauthPort))

	if err := os.WriteFile(path, []byte(conf), 0o644); err != nil {
		t.Fatalf("запись конфига: %v", err)
	}

	listen := cfg.ListenPorts()[0]
	hostPort := freePort(t)

	// Без --rm: упавший контейнер нужно успеть расспросить.
	out, err := exec.Command("docker", "run", "-d",
		"-v", dir+":"+confDir+":ro",
		"-p", fmt.Sprintf("127.0.0.1:%d:%d", hostPort, listen),
		nginxImage,
		"nginx", "-c", confDir+"/nginx.conf", "-g", "daemon off;",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("запуск nginx: %v\n%s", err, out)
	}

	id := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		if t.Failed() {
			status, _ := exec.Command("docker", "inspect", "-f", "{{.State.Status}} {{.State.ExitCode}}", id).CombinedOutput()
			logs, _ := exec.Command("docker", "logs", id).CombinedOutput()
			t.Logf("nginx: %s\n%s", status, logs)
		}
		exec.Command("docker", "rm", "-f", id).Run()
	})

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			// Куда бы ни вёл адрес, идём в наш контейнер: имя домена
			// нужно только для SNI и заголовка Host.
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, fmt.Sprintf("127.0.0.1:%d", hostPort))
			},
		},
		// Редиректы не проходим: тесту важен сам ответ nginx.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	waitReady(t, client, cfg.Endpoints[0])
	return client
}

// waitReady ждёт, пока ответит сам nginx. Открытого порта мало:
// опубликованный порт принимает соединения ещё до старта контейнера, и
// запрос в этот момент обрывается на рукопожатии TLS.
func waitReady(t *testing.T, client *http.Client, e agent.Endpoint) {
	t.Helper()

	url := fmt.Sprintf("https://%s:%d/", e.Domain, e.Listen)

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("nginx не начал отвечать")
}

func freePort(t *testing.T) int {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("свободный порт: %v", err)
	}
	defer l.Close()

	_, port, _ := net.SplitHostPort(l.Addr().String())

	var n int
	fmt.Sscanf(port, "%d", &n)
	return n
}

// backendSaw — заголовки, которые увидел бэкенд.
func backendSaw(t *testing.T, client *http.Client, url string, headers map[string]string) http.Header {
	t.Helper()

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("запрос: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("запрос к nginx: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("код = %d, ожидался 200: %s", resp.StatusCode, body)
	}

	var got struct {
		Headers http.Header `json:"headers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("разбор ответа бэкенда: %v", err)
	}
	return got.Headers
}

// Клиент не должен уметь представиться бэкенду вошедшим. Проверяется на
// живом nginx: подделанные заголовки шлются с запросом и не должны
// доехать ни на открытом эндпоинте, ни на пути мимо авторизации.
func TestProxyDropsSpoofedAuthHeaders(t *testing.T) {
	echo := startEcho(t)
	stub := startOAuthStub(t)

	cfg := &agent.Config{
		OAuth: func() agent.OAuthConfig {
			o := baseOAuth()
			return o
		}(),
		Endpoints: []agent.Endpoint{
			{
				Domain: "open.example.com", Listen: 8443,
				Upstream: upstreamTo(t, echo.Server),
			},
			{
				Domain: "docs.example.com", Listen: 8443,
				Upstream: upstreamTo(t, echo.Server),
				OAuth: &agent.EndpointOAuth{
					Groups:    []string{"platform/sre"},
					SkipPaths: []string{"/api/"},
				},
			},
		},
	}

	client := runNginx(t, cfg, portOf(t, stub.Server))

	spoofed := map[string]string{
		"X-Auth-Request-User":               "самозванец",
		"X-Auth-Request-Email":              "hacker@example.com",
		"X-Auth-Request-Groups":             "platform/sre,admins",
		"X-Auth-Request-Preferred-Username": "самозванец",
		"X-Auth-Request-Access-Token":       "поддельный-токен",
	}

	t.Run("открытый эндпоинт", func(t *testing.T) {
		got := backendSaw(t, client, "https://open.example.com:8443/", spoofed)

		for name := range spoofed {
			if v := got.Get(name); v != "" {
				t.Errorf("до бэкенда доехал подделанный %s = %q", name, v)
			}
		}
	})

	t.Run("путь мимо авторизации", func(t *testing.T) {
		got := backendSaw(t, client, "https://docs.example.com:8443/api/v1", spoofed)

		for name := range spoofed {
			if v := got.Get(name); v != "" {
				t.Errorf("до бэкенда доехал подделанный %s = %q", name, v)
			}
		}
	})

	t.Run("закрытый путь — значения от прокси, а не от клиента", func(t *testing.T) {
		got := backendSaw(t, client, "https://docs.example.com:8443/", spoofed)

		if v := got.Get("X-Auth-Request-User"); v != "настоящий-пользователь" {
			t.Errorf("X-Auth-Request-User = %q, ожидалось значение от прокси", v)
		}
		if v := got.Get("X-Auth-Request-Email"); v != "real@example.com" {
			t.Errorf("X-Auth-Request-Email = %q", v)
		}
		if v := got.Get("X-Auth-Request-Preferred-Username"); v != "настоящий-ник" {
			t.Errorf("X-Auth-Request-Preferred-Username = %q", v)
		}
		// Токен прокси не запрашивает, значит клиентский должен исчезнуть.
		if v := got.Get("X-Auth-Request-Access-Token"); v != "" {
			t.Errorf("до бэкенда доехал подделанный токен: %q", v)
		}
		// Заголовок не должен уйти дважды: nginx отправил бы оба значения.
		if vs := got.Values("X-Auth-Request-User"); len(vs) != 1 {
			t.Errorf("X-Auth-Request-User пришёл %d раз: %v", len(vs), vs)
		}
	})
}

// Признаки «настоящего» адреса запроса задаёт прокси: по ним приложения
// строят ссылки, а некоторые фреймворки подменяют путь.
func TestProxyControlsForwardedHeaders(t *testing.T) {
	echo := startEcho(t)

	cfg := &agent.Config{
		Endpoints: []agent.Endpoint{{
			Domain: "app.example.com", Listen: 8443,
			Upstream: upstreamTo(t, echo.Server),
		}},
	}

	client := runNginx(t, cfg, 0)

	got := backendSaw(t, client, "https://app.example.com:8443/", map[string]string{
		"X-Forwarded-Host":   "evil.example.com",
		"X-Forwarded-Proto":  "http",
		"X-Forwarded-Port":   "80",
		"X-Forwarded-Prefix": "/admin",
		"X-Forwarded-Uri":    "/admin",
		"X-Forwarded-Ssl":    "off",
		"X-Original-URL":     "/admin",
		"X-Rewrite-URL":      "/admin",
		"X-Url-Scheme":       "http",
	})

	for name, want := range map[string]string{
		"X-Forwarded-Host":  "app.example.com",
		"X-Forwarded-Proto": "https",
		"X-Forwarded-Port":  "8443",
	} {
		if v := got.Get(name); v != want {
			t.Errorf("%s = %q, ожидалось %q — значение задаёт прокси", name, v, want)
		}
	}

	for _, name := range []string{
		"X-Forwarded-Prefix", "X-Forwarded-Uri", "X-Forwarded-Ssl",
		"X-Original-URL", "X-Rewrite-URL", "X-Url-Scheme",
	} {
		if v := got.Get(name); v != "" {
			t.Errorf("до бэкенда доехал подделанный %s = %q", name, v)
		}
	}
}

// Ограничение по группам уходит в подзапрос: при общем входе процесс
// один на все домены, и различить их можно только так.
func TestProxyPassesAllowedGroups(t *testing.T) {
	echo := startEcho(t)
	stub := startOAuthStub(t)

	o := baseOAuth()
	o.AuthDomain = "auth.example.com"

	upstream := upstreamTo(t, echo.Server)

	cfg := &agent.Config{
		OAuth: o,
		Endpoints: []agent.Endpoint{
			{Domain: "auth.example.com", Listen: 8443, Upstream: upstream},
			{
				Domain: "docs.example.com", Listen: 8443, Upstream: upstream,
				OAuth: &agent.EndpointOAuth{Groups: []string{"platform/backend", "platform/sre"}},
			},
		},
	}

	client := runNginx(t, cfg, portOf(t, stub.Server))

	backendSaw(t, client, "https://docs.example.com:8443/", nil)

	want := "allowed_groups=platform%2Fbackend,platform%2Fsre"
	if stub.lastAuthQuery != want {
		t.Errorf("строка запроса подзапроса = %q, ожидалась %q", stub.lastAuthQuery, want)
	}
}

// Неавторизованного уводят на вход, а не пускают к бэкенду.
func TestProxyRedirectsAnonymousToLogin(t *testing.T) {
	echo := startEcho(t)
	stub := startOAuthStub(t)
	stub.authorized = false

	cfg := &agent.Config{
		OAuth: baseOAuth(),
		Endpoints: []agent.Endpoint{{
			Domain: "docs.example.com", Listen: 8443,
			Upstream: upstreamTo(t, echo.Server),
			OAuth:    &agent.EndpointOAuth{},
		}},
	}

	client := runNginx(t, cfg, portOf(t, stub.Server))

	resp, err := client.Get("https://docs.example.com:8443/секрет")
	if err != nil {
		t.Fatalf("запрос: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "headers") {
		t.Fatalf("запрос без сессии дошёл до бэкенда: %s", body)
	}
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "вход") {
		t.Fatalf("код = %d, тело = %q — ожидался экран входа", resp.StatusCode, body)
	}
}

// Поток должен доходить по мере появления. С буферизацией nginx придержит
// первую часть до конца ответа, и запрос выглядит зависшим — так ломался
// /api/v1/notifications/live у Prometheus.
func TestProxyStreamsWithoutBuffering(t *testing.T) {
	echo := startEcho(t)

	cfg := &agent.Config{
		Endpoints: []agent.Endpoint{{
			Domain: "app.example.com", Listen: 8443,
			Upstream: upstreamTo(t, echo.Server),
		}},
	}

	client := runNginx(t, cfg, 0)

	started := time.Now()

	resp, err := client.Get("https://app.example.com:8443/stream")
	if err != nil {
		t.Fatalf("запрос: %v", err)
	}
	defer resp.Body.Close()

	buf := make([]byte, len("data: первая\n\n"))
	if _, err := io.ReadFull(resp.Body, buf); err != nil {
		t.Fatalf("чтение первой части потока: %v", err)
	}

	// Бэкенд держит соединение три секунды после первой части.
	if waited := time.Since(started); waited > 2*time.Second {
		t.Errorf("первая часть потока пришла через %v — ответ буферизуется", waited.Round(time.Millisecond))
	}
	if got := string(buf); got != "data: первая\n\n" {
		t.Errorf("получено %q", got)
	}
}
