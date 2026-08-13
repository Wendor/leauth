package agent

import (
	"encoding/base64"
	"strings"
	"testing"
)

func renderToString(t *testing.T, endpoints []Endpoint, certDir string) string {
	t.Helper()

	var sb strings.Builder
	if err := RenderNginxConfig(&sb, &Config{Endpoints: endpoints, CertDir: certDir}); err != nil {
		t.Fatalf("RenderNginxConfig: %v", err)
	}
	return sb.String()
}

func TestRenderSingleEndpoint(t *testing.T) {
	out := renderToString(t, []Endpoint{
		{Domain: "foo.example.com", Listen: 8443, Upstream: "http://app:3000"},
	}, "/etc/leauth/certs")

	for _, want := range []string{
		"listen 8443 ssl;",
		"server_name foo.example.com;",
		"ssl_certificate     /etc/leauth/certs/foo.example.com/fullchain.pem;",
		"ssl_certificate_key /etc/leauth/certs/foo.example.com/privkey.pem;",
		"set $upstream http://app:3000;",
		"proxy_pass $upstream$request_uri;",
		"proxy_set_header Host              $host;",
		"proxy_set_header X-Forwarded-Proto https;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("в конфиге нет %q\n---\n%s", want, out)
		}
	}
}

// Апстрим обязан резолвиться лениво: reload не должен падать из-за
// недоступного бэкенда.
func TestRenderUsesLazyUpstreamResolution(t *testing.T) {
	out := renderToString(t, []Endpoint{
		{Domain: "a.example.com", Listen: 8443, Upstream: "http://app:80"},
	}, "/certs")

	if !strings.Contains(out, "resolver "+DefaultResolver) {
		t.Errorf("в конфиге нет директивы resolver по умолчанию\n---\n%s", out)
	}

	var sb strings.Builder
	if err := RenderNginxConfig(&sb, &Config{
		Endpoints: []Endpoint{{Domain: "a.example.com", Listen: 8443, Upstream: "http://app:80"}},
		CertDir:   "/certs",
		Resolver:  "10.0.0.53",
	}); err != nil {
		t.Fatalf("RenderNginxConfig: %v", err)
	}
	if !strings.Contains(sb.String(), "resolver 10.0.0.53") {
		t.Error("заданный резолвер не попал в конфиг")
	}
}

func TestRenderMultipleEndpoints(t *testing.T) {
	out := renderToString(t, []Endpoint{
		{Domain: "a.example.com", Listen: 8443, Upstream: "http://a:80"},
		{Domain: "b.example.com", Listen: 9443, Upstream: "http://b:80"},
	}, "/certs")

	// Два эндпоинта плюс по заглушке на каждый занятый порт.
	if n := strings.Count(out, "server {"); n != 4 {
		t.Errorf("блоков server: %d, ожидалось 4", n)
	}
	if !strings.Contains(out, "listen 9443 ssl;") {
		t.Error("нет второго порта")
	}
}

// Домены на одном порту различаются по SNI: порт публикуется один раз,
// а адреса эндпоинтов остаются без второго номера порта.
func TestRenderSharedPort(t *testing.T) {
	out := renderToString(t, []Endpoint{
		{Domain: "a.example.com", Listen: 8443, Upstream: "http://a:80"},
		{Domain: "b.example.com", Listen: 8443, Upstream: "http://b:80"},
	}, "/certs")

	for _, want := range []string{"server_name a.example.com;", "server_name b.example.com;"} {
		if !strings.Contains(out, want) {
			t.Errorf("в конфиге нет %q\n---\n%s", want, out)
		}
	}
	if n := strings.Count(out, "listen 8443 ssl;"); n != 2 {
		t.Errorf("блоков на общем порту: %d, ожидалось 2", n)
	}
}

// Запрос с чужим SNI не должен попадать в первый блок порта: без
// заглушки клиент получил бы сертификат чужого домена.
func TestRenderDefaultServerPerPort(t *testing.T) {
	out := renderToString(t, []Endpoint{
		{Domain: "a.example.com", Listen: 8443, Upstream: "http://a:80"},
		{Domain: "b.example.com", Listen: 8443, Upstream: "http://b:80"},
		{Domain: "c.example.com", Listen: 9443, Upstream: "http://c:80"},
	}, "/certs")

	for _, want := range []string{"listen 8443 ssl default_server;", "listen 9443 ssl default_server;"} {
		if !strings.Contains(out, want) {
			t.Errorf("нет заглушки: %q\n---\n%s", want, out)
		}
	}
	if n := strings.Count(out, "default_server"); n != 2 {
		t.Errorf("заглушек: %d, ожидалось по одной на порт", n)
	}
	if !strings.Contains(out, "return 421;") {
		t.Error("заглушка должна отвечать 421, а не проксировать")
	}
}

func TestRenderIncludesHTTPBlock(t *testing.T) {
	out := renderToString(t, []Endpoint{
		{Domain: "a.example.com", Listen: 8443, Upstream: "http://a:80"},
	}, "/certs")

	for _, want := range []string{"events {", "http {", "worker_processes"} {
		if !strings.Contains(out, want) {
			t.Errorf("конфиг не самодостаточен, нет %q", want)
		}
	}
}

// Эндпоинты одной зоны обслуживает один сертификат: nginx должен
// смотреть в его каталог, а не в каталог собственного домена.
func TestRenderUsesZoneCertificate(t *testing.T) {
	var sb strings.Builder

	err := RenderNginxConfig(&sb, &Config{
		CertDir:       "/certs",
		WildcardZones: []string{"example.com"},
		Endpoints: []Endpoint{
			{Domain: "docs.example.com", Listen: 8443, Upstream: "http://docs:80"},
			{Domain: "app.other.net", Listen: 8444, Upstream: "http://app:80"},
		},
	})
	if err != nil {
		t.Fatalf("RenderNginxConfig: %v", err)
	}
	out := sb.String()

	for _, want := range []string{
		"ssl_certificate     /certs/example.com/fullchain.pem;",
		"ssl_certificate_key /certs/example.com/privkey.pem;",
		"ssl_certificate     /certs/app.other.net/fullchain.pem;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("в конфиге нет %q\n---\n%s", want, out)
		}
	}

	if strings.Contains(out, "/certs/docs.example.com/") {
		t.Errorf("поддомен зоны не должен иметь своего сертификата\n---\n%s", out)
	}
}

// Бэкенд со своей basic-авторизацией: прокси подставляет реквизиты сам,
// заменяя заголовок, присланный клиентом.
func TestRenderUpstreamAuth(t *testing.T) {
	out := renderToString(t, []Endpoint{{
		Domain:       "prom.example.com",
		Listen:       8443,
		Upstream:     "http://metrics:9090",
		UpstreamAuth: &UpstreamAuth{User: "admin", Password: "секрет"},
	}}, "/certs")

	creds := `"Basic ` + base64.StdEncoding.EncodeToString([]byte("admin:секрет")) + `";`

	for _, want := range []string{
		"map $http_authorization $upstream_auth_0 {",
		creds,
		"default $http_authorization;",
		"proxy_set_header Authorization $upstream_auth_0;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("в конфиге нет %q\n---\n%s", want, out)
		}
	}
}

// Реквизиты бэкенда не должны затирать заголовок машинного клиента:
// под тем же адресом живёт API со своими токенами.
func TestRenderUpstreamAuthKeepsClientHeader(t *testing.T) {
	out := renderToString(t, []Endpoint{{
		Domain:       "leauth.example.com",
		Listen:       443,
		Upstream:     "http://127.0.0.1:8080",
		UpstreamAuth: &UpstreamAuth{User: "admin", Password: "пароль"},
	}}, "/certs")

	// Подстановка идёт через map: пустой заголовок заменяется, любой
	// присланный клиентом доходит до бэкенда как есть.
	if strings.Contains(out, `proxy_set_header Authorization "Basic`) {
		t.Errorf("заголовок подставляется безусловно\n---\n%s", out)
	}
}

// Без блока upstream_auth заголовок не появляется: клиентский проходит
// насквозь, как и раньше.
func TestRenderWithoutUpstreamAuth(t *testing.T) {
	out := renderToString(t, []Endpoint{
		{Domain: "a.example.com", Listen: 8443, Upstream: "http://a:80"},
	}, "/certs")

	if strings.Contains(out, "proxy_set_header Authorization") {
		t.Errorf("лишний заголовок авторизации\n---\n%s", out)
	}
}

// За прокси живут потоковые ответы: server-sent events, вывод логов,
// вебсокеты. С буферизацией такой ответ копится в nginx и до клиента не
// доходит — запрос выглядит зависшим, пока не сработает таймаут.
func TestRenderSupportsStreaming(t *testing.T) {
	out := renderToString(t, []Endpoint{
		{Domain: "prom.example.com", Listen: 443, Upstream: "http://127.0.0.1:9090"},
	}, "/certs")

	for _, want := range []string{
		"proxy_buffering off;",
		// Молчащий поток не должен обрываться дефолтной минутой.
		"proxy_read_timeout 1h;",
		// Вебсокеты: апгрейд соединения был и остаётся.
		"proxy_http_version 1.1;",
		"proxy_set_header Upgrade    $http_upgrade;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("в конфиге нет %q\n---\n%s", want, out)
		}
	}
}

// Заголовки о «настоящем» адресе запроса задаёт прокси, а не клиент: по
// ним приложения строят абсолютные ссылки, а некоторые фреймворки
// подменяют путь — тогда запрос, пропущенный мимо авторизации по одному
// пути, обрабатывается как другой.
func TestRenderControlsForwardedHeaders(t *testing.T) {
	out := renderToString(t, []Endpoint{
		{Domain: "app.example.com", Listen: 8443, Upstream: "http://app:3000"},
	}, "/certs")

	for _, want := range []string{
		"proxy_set_header X-Forwarded-Host  $host;",
		"proxy_set_header X-Forwarded-Port  $server_port;",
		`proxy_set_header X-Forwarded-Prefix "";`,
		`proxy_set_header X-Forwarded-Uri    "";`,
		`proxy_set_header X-Forwarded-Server "";`,
		`proxy_set_header X-Forwarded-Ssl    "";`,
		`proxy_set_header X-Url-Scheme       "";`,
		`proxy_set_header X-Original-URL     "";`,
		`proxy_set_header X-Rewrite-URL      "";`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("в конфиге нет %q\n---\n%s", want, out)
		}
	}
}

// oauth2-proxy доверяет X-Forwarded-* от локального nginx, поэтому имя
// хоста в служебных блоках задаём мы, а не тот, кто пришёл.
func TestRenderSetsForwardedHostForOAuthEndpoints(t *testing.T) {
	out := renderToString(t, []Endpoint{{
		Domain: "docs.example.com", Listen: 8443, Upstream: "http://docs:8080",
		OAuth: &EndpointOAuth{},
	}}, "/certs")

	// Три служебных блока: /oauth2/, /oauth2/sign_out и подзапрос.
	if n := strings.Count(out, "proxy_set_header X-Forwarded-Host"); n < 4 {
		t.Errorf("X-Forwarded-Host задан %d раз — служебные блоки его пропускают\n---\n%s", n, out)
	}
}
