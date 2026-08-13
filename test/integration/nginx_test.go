//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"leauth/internal/agent"
)

// nginxImage — тот же образ, на котором работает прокси. Проверять конфиг
// чем-то другим смысла нет: директивы и пути должны совпасть с боевыми.
const nginxImage = "nginx:1.29-alpine"

// confDir — куда каталог с конфигом монтируется внутрь контейнера.
// Пути сертификатов в конфиге абсолютные, поэтому имя фиксировано.
const confDir = "/conf"

// prepareNginx раскладывает конфиг и сертификаты так, как их увидит nginx
// в контейнере, и возвращает каталог на хосте.
//
// Сертификаты настоящие: nginx читает их при загрузке конфига и на
// отсутствующий файл ругается так же, как на синтаксическую ошибку.
func prepareNginx(t *testing.T, cfg *agent.Config) string {
	t.Helper()

	// Симлинки резолвятся: на macOS t.TempDir отдаёт путь через
	// /var/folders, а это симлинк на /private/var/folders. Docker его не
	// разворачивает и молча монтирует пустой каталог.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("каталог конфига: %v", err)
	}
	cfg.CertDir = confDir + "/certs"

	certs := agent.NewCertDir(filepath.Join(dir, "certs"))
	for _, c := range cfg.Certificates() {
		certPEM, keyPEM, err := agent.GenerateSelfSigned(c.Names()...)
		if err != nil {
			t.Fatalf("сертификат для %s: %v", c.Domain, err)
		}
		if err := certs.Write(c.Domain, certPEM, keyPEM); err != nil {
			t.Fatalf("запись сертификата %s: %v", c.Domain, err)
		}
	}

	var sb strings.Builder
	if err := agent.RenderNginxConfig(&sb, cfg); err != nil {
		t.Fatalf("рендер конфига: %v", err)
	}

	path := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		t.Fatalf("запись конфига: %v", err)
	}
	return dir
}

// checkNginxConfig скармливает сгенерированный конфиг настоящему nginx.
// Сравнения строк в модульных тестах ловят подстановку значений, но не
// отвечают на главный вопрос — примет ли этот текст nginx вообще.
func checkNginxConfig(t *testing.T, cfg *agent.Config) {
	t.Helper()

	dir := prepareNginx(t, cfg)

	out, err := exec.Command("docker", "run", "--rm",
		"-v", dir+":"+confDir+":ro",
		nginxImage,
		"nginx", "-t", "-c", confDir+"/nginx.conf",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("nginx не принял конфиг: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "syntax is ok") {
		t.Errorf("неожиданный ответ nginx:\n%s", out)
	}
}

// baseOAuth — реквизиты, без которых конфиг с авторизацией не пройдёт
// собственную валидацию.
func baseOAuth() agent.OAuthConfig {
	return agent.OAuthConfig{
		Issuer:       "https://gitlab.example.com",
		ClientID:     "клиент",
		ClientSecret: "секрет",
		CookieSecret: "0123456789abcdef",
	}
}

// TestNginxAcceptsGeneratedConfig прогоняет через nginx каждое сочетание
// возможностей конфига. Все ошибки шаблона, которые находились до сих пор,
// жили именно здесь: сравнение строк их не видит, а прокси с негодным
// конфигом просто не поднимается.
func TestNginxAcceptsGeneratedConfig(t *testing.T) {
	cases := map[string]*agent.Config{
		"открытый эндпоинт": {
			Endpoints: []agent.Endpoint{
				{Domain: "app.example.com", Listen: 8443, Upstream: "http://app:3000"},
			},
		},
		"несколько доменов на одном порту": {
			Endpoints: []agent.Endpoint{
				{Domain: "a.example.com", Listen: 8443, Upstream: "http://a:80"},
				{Domain: "b.example.com", Listen: 8443, Upstream: "http://b:80"},
			},
		},
		"разные порты": {
			Endpoints: []agent.Endpoint{
				{Domain: "a.example.com", Listen: 8443, Upstream: "http://a:80"},
				{Domain: "b.example.com", Listen: 9443, Upstream: "http://b:80"},
			},
		},
		"wildcard-зона": {
			WildcardZones: []string{"example.com"},
			Endpoints: []agent.Endpoint{
				{Domain: "a.example.com", Listen: 8443, Upstream: "http://a:80"},
				{Domain: "b.example.com", Listen: 8443, Upstream: "http://b:80"},
			},
		},
		"реквизиты бэкенда": {
			Endpoints: []agent.Endpoint{
				{
					Domain: "prom.example.com", Listen: 8443, Upstream: "http://prom:9090",
					UpstreamAuth: &agent.UpstreamAuth{User: "admin", Password: "пароль"},
				},
			},
		},
		"авторизация на эндпоинт": {
			OAuth: baseOAuth(),
			Endpoints: []agent.Endpoint{
				{
					Domain: "docs.example.com", Listen: 8443, Upstream: "http://docs:8080",
					OAuth: &agent.EndpointOAuth{Groups: []string{"platform/backend"}},
				},
				{Domain: "open.example.com", Listen: 8443, Upstream: "http://open:80"},
			},
		},
		"пути мимо авторизации": {
			OAuth: baseOAuth(),
			Endpoints: []agent.Endpoint{
				{
					Domain: "leauth.example.com", Listen: 443, Upstream: "http://127.0.0.1:8080",
					OAuth: &agent.EndpointOAuth{
						Groups:    []string{"platform/sre"},
						SkipPaths: []string{"/api/", "/healthz"},
					},
				},
			},
		},
		"общий вход": {
			OAuth: func() agent.OAuthConfig {
				o := baseOAuth()
				o.AuthDomain = "auth.example.com"
				return o
			}(),
			Endpoints: []agent.Endpoint{
				{Domain: "auth.example.com", Listen: 8443, Upstream: "http://stub:80"},
				{
					Domain: "docs.example.com", Listen: 8443, Upstream: "http://docs:8080",
					OAuth: &agent.EndpointOAuth{Groups: []string{"platform/backend"}},
				},
				{
					Domain: "wiki.example.com", Listen: 8443, Upstream: "http://wiki:8080",
					OAuth: &agent.EndpointOAuth{},
				},
			},
		},
		"всё сразу": {
			OAuth: func() agent.OAuthConfig {
				o := baseOAuth()
				o.AuthDomain = "auth.example.com"
				return o
			}(),
			WildcardZones: []string{"example.com"},
			Endpoints: []agent.Endpoint{
				{Domain: "auth.example.com", Listen: 8443, Upstream: "http://stub:80"},
				{
					Domain: "prom.example.com", Listen: 8443, Upstream: "http://prom:9090",
					UpstreamAuth: &agent.UpstreamAuth{User: "admin", Password: "пароль"},
					OAuth: &agent.EndpointOAuth{
						Groups:    []string{"platform/sre"},
						SkipPaths: []string{"/api/"},
					},
				},
				{Domain: "open.example.com", Listen: 9443, Upstream: "https://open:443"},
			},
		},
	}

	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			// Конфиг обязан проходить и собственную валидацию: тест не
			// должен проверять то, чего агент не примет.
			cfg.Server = "https://leauth.example.com"
			cfg.Name = "srv-01"
			if err := cfg.Validate(); err != nil {
				t.Fatalf("конфиг не прошёл валидацию агента: %v", err)
			}

			checkNginxConfig(t, cfg)
		})
	}
}
