package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeAgentConfig(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("запись конфига: %v", err)
	}
	return path
}

func TestLoadConfig(t *testing.T) {
	t.Setenv("LEAUTH_TOKEN", "токен-1")

	cfg, err := LoadConfig(writeAgentConfig(t, `
server: https://leauth.example.com
name: srv-01
enroll_token: ${LEAUTH_TOKEN}
poll_interval: 1h
wildcard_zones:
  - example.com
endpoints:
  - domain: foo.example.com
    listen: 8443
    upstream: http://app:3000
  - domain: bar.example.com
    listen: 9443
    upstream: http://other:8080
`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.EnrollToken != "токен-1" {
		t.Errorf("enroll_token = %q", cfg.EnrollToken)
	}
	if cfg.Name != "srv-01" {
		t.Errorf("name = %q", cfg.Name)
	}
	if cfg.PollInterval.Duration() != time.Hour {
		t.Errorf("poll_interval = %v", cfg.PollInterval.Duration())
	}
	if cfg.CertDir != "/etc/leauth/certs" {
		t.Errorf("cert_dir по умолчанию = %q", cfg.CertDir)
	}
	if len(cfg.Endpoints) != 2 {
		t.Fatalf("эндпоинтов: %d", len(cfg.Endpoints))
	}
	// Оба эндпоинта лежат в объявленной зоне, значит сертификат один.
	certs := cfg.Certificates()
	if len(certs) != 1 || certs[0].Domain != "example.com" || !certs[0].Wildcard {
		t.Errorf("сертификаты = %+v", certs)
	}
}

func TestLoadConfigRejectsZoneWithStar(t *testing.T) {
	t.Setenv("LEAUTH_TOKEN", "токен-1")

	_, err := LoadConfig(writeAgentConfig(t, `
server: https://leauth.example.com
name: srv-01
enroll_token: ${LEAUTH_TOKEN}
wildcard_zones:
  - "*.example.com"
endpoints:
  - domain: foo.example.com
    listen: 8443
    upstream: http://app:3000
`))
	if err == nil {
		t.Fatal("зона со звёздочкой должна отвергаться")
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	t.Setenv("LEAUTH_TOKEN", "токен-1")

	cfg, err := LoadConfig(writeAgentConfig(t, `
server: https://leauth.example.com
name: srv-01
enroll_token: ${LEAUTH_TOKEN}
endpoints:
  - domain: foo.example.com
    listen: 8443
    upstream: http://app:3000
`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.PollInterval.Duration() != time.Hour {
		t.Errorf("poll_interval по умолчанию = %v", cfg.PollInterval.Duration())
	}
}

// Домены различаются по SNI, поэтому общий порт — нормальный конфиг,
// а не опечатка: так адреса эндпоинтов остаются одинаковой формы.
func TestLoadConfigAllowsSharedPort(t *testing.T) {
	t.Setenv("LEAUTH_TOKEN", "токен-1")

	cfg, err := LoadConfig(writeAgentConfig(t, `
server: https://leauth.example.com
name: srv-01
enroll_token: ${LEAUTH_TOKEN}
endpoints:
  - domain: a.example.com
    listen: 8443
    upstream: http://a:3000
  - domain: b.example.com
    listen: 8443
    upstream: http://b:3000
`))
	if err != nil {
		t.Fatalf("общий порт отвергнут: %v", err)
	}
	if len(cfg.Endpoints) != 2 {
		t.Fatalf("эндпоинтов: %d", len(cfg.Endpoints))
	}
}

func TestLoadConfigValidation(t *testing.T) {
	t.Setenv("LEAUTH_TOKEN", "токен-1")

	cases := map[string]string{
		"без сервера":           "name: srv-01\nendpoints:\n  - {domain: a.example.com, listen: 8443, upstream: 'http://a'}\n",
		"плохое имя":            "server: https://c\nname: 'srv 01'\nendpoints:\n  - {domain: a.example.com, listen: 8443, upstream: 'http://a'}\n",
		"без эндпоинтов":        "server: https://c\nname: srv-01\n",
		"плохой порт":           "server: https://c\nname: srv-01\nendpoints:\n  - {domain: a.example.com, listen: 70000, upstream: 'http://a'}\n",
		"upstream без схемы":    "server: https://c\nname: srv-01\nendpoints:\n  - {domain: a.example.com, listen: 8443, upstream: 'app:3000'}\n",
		"повтор домена и порта": "server: https://c\nname: srv-01\nendpoints:\n  - {domain: a.example.com, listen: 8443, upstream: 'http://a'}\n  - {domain: a.example.com, listen: 8443, upstream: 'http://b'}\n",
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadConfig(writeAgentConfig(t, body)); err == nil {
				t.Fatal("ожидалась ошибка валидации")
			}
		})
	}
}

func TestLoadConfigUpstreamAuth(t *testing.T) {
	t.Setenv("LEAUTH_TOKEN", "токен-1")
	t.Setenv("PROM_PASSWORD", "пароль-бэкенда")

	cfg, err := LoadConfig(writeAgentConfig(t, `
server: https://leauth.example.com
name: srv-01
enroll_token: ${LEAUTH_TOKEN}
endpoints:
  - domain: prom.example.com
    listen: 8443
    upstream: http://metrics:9090
    upstream_auth:
      user: admin
      password: ${PROM_PASSWORD}
`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	u := cfg.Endpoints[0].UpstreamAuth
	if u == nil {
		t.Fatal("upstream_auth не разобран")
	}
	if u.Password != "пароль-бэкенда" {
		t.Errorf("пароль не подставлен из окружения: %q", u.Password)
	}
}

func TestValidateUpstreamAuth(t *testing.T) {
	cases := map[string]*UpstreamAuth{
		"без пароля":         {User: "admin"},
		"без логина":         {Password: "пароль"},
		"двоеточие в логине": {User: "ad:min", Password: "пароль"},
	}

	for name, auth := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := &Config{
				Server: "https://leauth.example.com",
				Name:   "srv-01",
				Endpoints: []Endpoint{{
					Domain:       "a.example.com",
					Listen:       8443,
					Upstream:     "http://a:80",
					UpstreamAuth: auth,
				}},
			}
			if err := cfg.Validate(); err == nil {
				t.Error("конфиг принят, хотя реквизиты неполны")
			}
		})
	}
}

// Домен и upstream попадают в конфиг nginx, поэтому проверяется их форма,
// а не только непустота: спецсимвол дописал бы в конфиг чужие директивы.
func TestLoadConfigRejectsInjectionInEndpoints(t *testing.T) {
	cases := map[string]string{
		"точка с запятой в домене": `
endpoints:
  - domain: "foo.example.com; return 200"
    listen: 8443
    upstream: http://app:3000`,
		"пробел в домене": `
endpoints:
  - domain: "foo example.com"
    listen: 8443
    upstream: http://app:3000`,
		"домен без точки": `
endpoints:
  - domain: localhost
    listen: 8443
    upstream: http://app:3000`,
		"переменная nginx в upstream": `
endpoints:
  - domain: foo.example.com
    listen: 8443
    upstream: "http://app:3000; proxy_set_header X-Auth-Request-User admin"`,
		"путь в upstream": `
endpoints:
  - domain: foo.example.com
    listen: 8443
    upstream: http://app:3000/prefix`,
		"upstream без адреса": `
endpoints:
  - domain: foo.example.com
    listen: 8443
    upstream: "http://"`,
	}

	for name, endpoints := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadConfig(writeAgentConfig(t, "server: https://leauth.example.com\nname: srv-01\n"+endpoints))
			if err == nil {
				t.Fatal("конфиг должен отвергаться")
			}
		})
	}
}

// Имя домена приводится к канону тем же кодом, что и на центре: иначе
// FOO.example.com завёл бы второй сертификат рядом с foo.example.com.
func TestLoadConfigNormalizesDomains(t *testing.T) {
	cfg, err := LoadConfig(writeAgentConfig(t, `
server: https://leauth.example.com
name: SRV-01
wildcard_zones:
  - Example.COM
endpoints:
  - domain: FOO.Example.com
    listen: 8443
    upstream: http://app:3000
`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.Name != "srv-01" {
		t.Errorf("имя прокси = %q", cfg.Name)
	}
	if cfg.Endpoints[0].Domain != "foo.example.com" {
		t.Errorf("домен = %q", cfg.Endpoints[0].Domain)
	}
	if cfg.WildcardZones[0] != "example.com" {
		t.Errorf("зона = %q", cfg.WildcardZones[0])
	}
	// Домен лежит в зоне, значит своего сертификата ему не нужно.
	if certs := cfg.Certificates(); len(certs) != 1 || certs[0].Domain != "example.com" {
		t.Errorf("сертификаты = %+v — нормализация не сработала", certs)
	}
}

// Порты нужны в логе при старте: публикует их docker, а знает только
// agent.yaml, и забытый в compose порт иначе никак себя не проявляет.
func TestListenPorts(t *testing.T) {
	cfg := &Config{Endpoints: []Endpoint{
		{Listen: 8443}, {Listen: 9443}, {Listen: 8443},
	}}

	got := cfg.ListenPorts()
	if len(got) != 2 || got[0] != 8443 || got[1] != 9443 {
		t.Errorf("порты = %v, ожидались [8443 9443] в порядке появления", got)
	}
}

// Общий вход ломается тихо: цикл логина или невидимая cookie выглядят
// одинаково непонятно, поэтому конфиг проверяется на старте.
func TestLoadConfigValidatesSharedOAuth(t *testing.T) {
	head := `
server: https://leauth.example.com
name: srv-01
oauth:
  issuer: https://gitlab.example.com
  client_id: id
  client_secret: secret
  cookie_secret: "0123456789abcdef"
`

	t.Run("домен входа не объявлен в endpoints", func(t *testing.T) {
		_, err := LoadConfig(writeAgentConfig(t, head+`  auth_domain: auth.example.com
endpoints:
  - domain: docs.example.com
    listen: 8443
    upstream: http://docs:8080
    oauth: {}
`))
		if err == nil || !strings.Contains(err.Error(), "auth_domain") {
			t.Fatalf("ошибка = %v — должна называть auth_domain", err)
		}
	})

	t.Run("домены из разных зон", func(t *testing.T) {
		_, err := LoadConfig(writeAgentConfig(t, head+`  auth_domain: auth.example.com
endpoints:
  - domain: auth.example.com
    listen: 8443
    upstream: http://static:80
  - domain: docs.other-company.net
    listen: 8443
    upstream: http://docs:8080
    oauth: {}
`))
		if err == nil || !strings.Contains(err.Error(), "общий вход невозможен") {
			t.Fatalf("ошибка = %v — cookie на два разных домена не поставить", err)
		}
	})

	t.Run("рабочая конфигурация", func(t *testing.T) {
		cfg, err := LoadConfig(writeAgentConfig(t, head+`  auth_domain: AUTH.Example.com
endpoints:
  - domain: auth.example.com
    listen: 8443
    upstream: http://static:80
  - domain: docs.example.com
    listen: 8443
    upstream: http://docs:8080
    oauth: {}
`))
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if cfg.OAuth.AuthDomain != "auth.example.com" {
			t.Errorf("auth_domain не приведён к канону: %q", cfg.OAuth.AuthDomain)
		}
		if !cfg.OAuth.Shared() {
			t.Error("общий вход не включился")
		}
	})
}
