package agent

import (
	"strconv"
	"strings"
	"testing"
)

func oauthConfig() *Config {
	return &Config{
		CertDir: "/certs",
		OAuth: OAuthConfig{
			Issuer:       "https://gitlab.example.com",
			ClientID:     "клиент",
			ClientSecret: "секрет",
			CookieSecret: "0123456789abcdef",
		},
		Endpoints: []Endpoint{
			{
				Domain:   "docs.example.com",
				Listen:   8443,
				Upstream: "http://app:3000",
				OAuth:    &EndpointOAuth{Groups: []string{"platform/backend"}},
			},
			{
				Domain:   "public.example.com",
				Listen:   7443,
				Upstream: "http://static:80",
			},
		},
	}
}

func TestRenderClosedEndpoint(t *testing.T) {
	var sb strings.Builder
	if err := RenderNginxConfig(&sb, oauthConfig()); err != nil {
		t.Fatalf("RenderNginxConfig: %v", err)
	}
	out := sb.String()

	for _, want := range []string{
		"location /oauth2/ {",
		"proxy_pass http://127.0.0.1:4180;",
		"location = /oauth2/auth {",
		"auth_request /oauth2/auth;",
		"error_page 401 = /oauth2/start;",
		// Без этого после логина пользователь попадёт на корень, а не туда,
		// куда шёл.
		"proxy_set_header X-Auth-Request-Redirect $request_uri;",
		// Личность бэкенду.
		"proxy_set_header X-Auth-Request-User               $auth_user;",
		"proxy_set_header X-Auth-Request-Email              $auth_email;",
		"proxy_set_header X-Auth-Request-Groups             $auth_groups;",
		// oauth2-proxy отдаёт его при --set-xauthrequest наравне с
		// остальными, значит и он должен браться из подзапроса.
		"proxy_set_header X-Auth-Request-Preferred-Username $auth_preferred;",
		// Продлённая сессия должна доехать до браузера, в том числе когда
		// бэкенд ответил ошибкой, — отсюда always.
		"add_header Set-Cookie $auth_cookie always;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("в конфиге нет %q\n---\n%s", want, out)
		}
	}
}

// Эндпоинт без блока oauth обязан остаться открытым: авторизация не должна
// протечь на соседний server-блок.
func TestRenderOpenEndpointStaysOpen(t *testing.T) {
	var sb strings.Builder
	if err := RenderNginxConfig(&sb, oauthConfig()); err != nil {
		t.Fatalf("RenderNginxConfig: %v", err)
	}

	_, open, found := strings.Cut(sb.String(), "server_name public.example.com;")
	if !found {
		t.Fatal("нет server-блока открытого эндпоинта")
	}

	for _, unwanted := range []string{"auth_request", "oauth2"} {
		if strings.Contains(open, unwanted) {
			t.Errorf("в открытом эндпоинте появилось %q\n---\n%s", unwanted, open)
		}
	}
}

// Порт oauth2-proxy в конфиге nginx обязан совпадать с тем, на котором
// процесс реально слушает.
func TestRenderUsesInstancePorts(t *testing.T) {
	cfg := &Config{
		CertDir: "/certs",
		OAuth: OAuthConfig{
			Issuer:       "https://gitlab.example.com",
			ClientID:     "клиент",
			ClientSecret: "секрет",
			CookieSecret: "0123456789abcdef",
		},
		Endpoints: []Endpoint{
			{Domain: "a.example.com", Listen: 8443, Upstream: "http://a:80", OAuth: &EndpointOAuth{}},
			{Domain: "open.example.com", Listen: 8444, Upstream: "http://b:80"},
			{Domain: "c.example.com", Listen: 8445, Upstream: "http://c:80", OAuth: &EndpointOAuth{}},
		},
	}

	var sb strings.Builder
	if err := RenderNginxConfig(&sb, cfg); err != nil {
		t.Fatalf("RenderNginxConfig: %v", err)
	}
	out := sb.String()

	for _, inst := range cfg.OAuthInstances() {
		_, block, _ := strings.Cut(out, "server_name "+inst.Endpoint.Domain+";")
		want := "proxy_pass http://127.0.0.1:" + strconv.Itoa(inst.Port) + ";"
		if !strings.Contains(block, want) {
			t.Errorf("для %s нет %q", inst.Endpoint.Domain, want)
		}
	}
}

// Пути из skip_paths проксируются мимо авторизации: по одному адресу
// живут страница для человека и машинный интерфейс.
func TestRenderSkipPaths(t *testing.T) {
	out := renderToString(t, []Endpoint{{
		Domain:   "leauth.example.com",
		Listen:   443,
		Upstream: "http://127.0.0.1:8080",
		OAuth:    &EndpointOAuth{Groups: []string{"platform/sre"}, SkipPaths: []string{"/api/"}},
	}}, "/certs")

	skip, rest, ok := strings.Cut(out, "location / {")
	if !ok {
		t.Fatalf("не найден корневой location\n---\n%s", out)
	}

	if !strings.Contains(skip, "location /api/ {") {
		t.Errorf("нет блока для /api/\n---\n%s", out)
	}
	// Всё, что идёт до корневого location, — служебные блоки и skip_paths.
	// auth_request там встречается только как внутренний подзапрос.
	if strings.Contains(skip, "auth_request /oauth2/auth;") {
		t.Errorf("skip_paths оказались под авторизацией\n---\n%s", skip)
	}
	if !strings.Contains(rest, "auth_request /oauth2/auth;") {
		t.Errorf("корневой location остался без авторизации\n---\n%s", rest)
	}
	if !strings.Contains(skip, "proxy_pass $upstream$request_uri;") {
		t.Errorf("skip_paths не проксируются на бэкенд\n---\n%s", skip)
	}
}

// Клиент не должен уметь представиться бэкенду вошедшим. Заголовки
// X-Auth-Request-* nginx по умолчанию проксирует как есть, поэтому везде,
// где авторизации нет, они обязаны затираться пустым значением.
func TestRenderClearsSpoofedAuthHeaders(t *testing.T) {
	// Эти прокси проставляет сам после проверки сессии — там, где
	// авторизации нет, их нужно занулять.
	fromSubrequest := []string{
		`proxy_set_header X-Auth-Request-User               "";`,
		`proxy_set_header X-Auth-Request-Email              "";`,
		`proxy_set_header X-Auth-Request-Groups             "";`,
		`proxy_set_header X-Auth-Request-Preferred-Username "";`,
	}
	// А эти прокси не проставляет никогда, поэтому прийти они могут
	// только от клиента и зануляются всегда — в том числе там, где
	// авторизация есть.
	alwaysCleared := []string{
		`proxy_set_header X-Auth-Request-Access-Token       "";`,
		`proxy_set_header X-Auth-Request-Redirect           "";`,
	}

	t.Run("эндпоинт без oauth", func(t *testing.T) {
		out := renderToString(t, []Endpoint{{
			Domain: "public.example.com", Listen: 8443, Upstream: "http://static:80",
		}}, "/certs")

		for _, want := range append(fromSubrequest, alwaysCleared...) {
			if !strings.Contains(out, want) {
				t.Errorf("открытый эндпоинт пропускает подделанный заголовок: нет %q\n---\n%s", want, out)
			}
		}
	})

	t.Run("skip_paths", func(t *testing.T) {
		out := renderToString(t, []Endpoint{{
			Domain:   "leauth.example.com",
			Listen:   443,
			Upstream: "http://127.0.0.1:8080",
			OAuth:    &EndpointOAuth{Groups: []string{"platform/sre"}, SkipPaths: []string{"/api/"}},
		}}, "/certs")

		skip, root, ok := strings.Cut(out, "location / {")
		if !ok {
			t.Fatalf("не найден корневой location\n---\n%s", out)
		}

		for _, want := range append(fromSubrequest, alwaysCleared...) {
			if !strings.Contains(skip, want) {
				t.Errorf("skip_paths пропускают подделанный заголовок: нет %q\n---\n%s", want, skip)
			}
		}

		// В корневом location заголовки не затираются, а задаются из
		// подзапроса: два proxy_set_header с одним именем ушли бы к
		// бэкенду обоими, и подделка проехала бы вместе с настоящим.
		for _, unwanted := range fromSubrequest {
			if strings.Contains(root, unwanted) {
				t.Errorf("в корневом location лишний сброс %q — заголовок уйдёт дважды\n---\n%s", unwanted, root)
			}
		}
		// Эти прокси не проставляет, поэтому они зануляются и здесь.
		for _, want := range alwaysCleared {
			if !strings.Contains(root, want) {
				t.Errorf("закрытый эндпоинт пропускает подделанный заголовок: нет %q\n---\n%s", want, root)
			}
		}
		if !strings.Contains(root, "proxy_set_header X-Auth-Request-User               $auth_user;") {
			t.Errorf("корневой location не передаёт личность бэкенду\n---\n%s", root)
		}
	})
}

// Выходу нужен свой адрес возврата. В общем блоке /oauth2/ заголовок
// X-Auth-Request-Redirect указывает на текущий запрос, то есть для
// выхода — на сам выход; oauth2-proxy берёт его, когда rd не задан или
// не прошёл проверку, и выход возвращает на выход.
func TestRenderSignOutRedirectsToRoot(t *testing.T) {
	t.Run("общий вход", func(t *testing.T) {
		var sb strings.Builder
		if err := RenderNginxConfig(&sb, sharedConfig()); err != nil {
			t.Fatalf("RenderNginxConfig: %v", err)
		}

		_, docs, _ := strings.Cut(sb.String(), "server_name docs.example.com;")
		docs, _, _ = strings.Cut(docs, "server_name ")

		if !strings.Contains(docs, "location = /oauth2/sign_out {") {
			t.Fatalf("нет отдельного блока выхода\n---\n%s", docs)
		}

		signOut := docs[strings.Index(docs, "location = /oauth2/sign_out {"):]
		signOut, _, _ = strings.Cut(signOut, "location = /oauth2/auth")

		if !strings.Contains(signOut, "proxy_set_header X-Auth-Request-Redirect https://docs.example.com:8443/;") {
			t.Errorf("выход не возвращает на корень своего домена\n---\n%s", signOut)
		}
		if strings.Contains(signOut, "$request_uri") {
			t.Errorf("выход возвращает на текущий запрос, то есть на сам выход\n---\n%s", signOut)
		}
	})

	t.Run("режим по умолчанию", func(t *testing.T) {
		var sb strings.Builder
		if err := RenderNginxConfig(&sb, oauthConfig()); err != nil {
			t.Fatalf("RenderNginxConfig: %v", err)
		}
		out := sb.String()

		if !strings.Contains(out, "location = /oauth2/sign_out {") {
			t.Fatalf("нет блока выхода\n---\n%s", out)
		}
		// Абсолютный адрес здесь не пройдёт: whitelist-domain не задан.
		if !strings.Contains(out, "proxy_set_header X-Auth-Request-Redirect /;") {
			t.Errorf("выход должен возвращать на корень относительным путём\n---\n%s", out)
		}
	})
}
