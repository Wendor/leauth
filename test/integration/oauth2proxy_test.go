//go:build integration

package integration

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"leauth/internal/agent"
)

// oauth2ProxyImage достаёт образ из Dockerfile прокси: проверять нужно
// ровно ту версию, которая попадёт в боевой образ, иначе тест разъедется
// с продом при первом же обновлении.
func oauth2ProxyImage(t *testing.T) string {
	t.Helper()

	raw, err := os.ReadFile("../../deploy/proxy/Dockerfile")
	if err != nil {
		t.Fatalf("чтение Dockerfile прокси: %v", err)
	}

	m := regexp.MustCompile(`FROM\s+(quay\.io/oauth2-proxy/oauth2-proxy:\S+)`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("в Dockerfile прокси не найден образ oauth2-proxy")
	}
	return string(m[1])
}

// TestOAuth2ProxyAcceptsOurArguments запускает oauth2-proxy ровно с теми
// аргументами, которые строит агент.
//
// Смысл проверки — не в том, что процесс поднимется (без GitLab он и не
// может), а в том, что он понимает каждый переданный флаг. Набор флагов
// это единственное место, где leauth зависит от версии oauth2-proxy, и
// молчаливое переименование флага при обновлении образа выяснилось бы
// только на живом прокси, оставшемся без авторизации.
func TestOAuth2ProxyAcceptsOurArguments(t *testing.T) {
	image := oauth2ProxyImage(t)

	shared := func(c *agent.Config) *agent.Config {
		c.OAuth.AuthDomain = "auth.example.com"
		c.Endpoints = append([]agent.Endpoint{
			{Domain: "auth.example.com", Listen: 8443, Upstream: "http://stub:80"},
		}, c.Endpoints...)
		return c
	}

	base := func() *agent.Config {
		return &agent.Config{
			Server: "https://leauth.example.com",
			Name:   "srv-01",
			OAuth:  baseOAuth(),
			Endpoints: []agent.Endpoint{{
				Domain: "docs.example.com", Listen: 8443, Upstream: "http://docs:8080",
				OAuth: &agent.EndpointOAuth{Groups: []string{"platform/backend", "platform/sre"}},
			}},
		}
	}

	cases := map[string]*agent.Config{
		"процесс на эндпоинт": base(),
		"общий вход":          shared(base()),
	}

	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if err := cfg.Validate(); err != nil {
				t.Fatalf("конфиг не прошёл валидацию агента: %v", err)
			}

			instances := cfg.OAuthInstances()
			if len(instances) == 0 {
				t.Fatal("агент не собрал ни одного процесса oauth2-proxy")
			}
			inst := instances[0]

			args := append([]string{"run", "--rm"}, envArgs(inst.Env(cfg.OAuth))...)
			args = append(args, image)
			args = append(args, inst.Args(cfg)...)

			out, err := exec.Command("docker", args...).CombinedOutput()
			text := string(out)

			// Неизвестный флаг — то, ради чего проверка и существует.
			if strings.Contains(text, "flag provided but not defined") ||
				strings.Contains(text, "unknown flag") {
				t.Fatalf("oauth2-proxy не понял аргументы агента:\n%s", text)
			}

			// Разбор конфигурации тоже должен пройти: об ошибках в
			// значениях (длина cookie-secret, форма redirect-url)
			// oauth2-proxy сообщает до всякой сети.
			if strings.Contains(text, "invalid configuration") {
				t.Fatalf("oauth2-proxy отверг конфигурацию:\n%s", text)
			}

			// Дальше он идёт в GitLab, которого в тесте нет, и падает —
			// это и есть признак, что все аргументы разобраны.
			if !strings.Contains(text, "Performing OIDC Discovery") {
				t.Fatalf("процесс не дошёл до обращения к GitLab (err=%v):\n%s", err, text)
			}
		})
	}
}

// envArgs превращает окружение процесса в аргументы docker run.
func envArgs(env []string) []string {
	var out []string
	for _, e := range env {
		out = append(out, "-e", e)
	}
	return out
}
