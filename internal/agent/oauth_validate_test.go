package agent

import (
	"strings"
	"testing"
)

// Конфиг с авторизацией, но без реквизитов GitLab, поднимется как открытый
// прокси — поэтому это ошибка запуска, а не предупреждение.
func TestValidateRequiresOAuthCredentials(t *testing.T) {
	t.Setenv("LEAUTH_TOKEN", "токен-1")

	_, err := LoadConfig(writeAgentConfig(t, `
server: https://leauth.example.com
token: ${LEAUTH_TOKEN}
endpoints:
  - domain: docs.example.com
    listen: 8443
    upstream: http://app:3000
    oauth: {}
`))
	if err == nil {
		t.Fatal("ожидалась ошибка")
	}
	for _, want := range []string{"issuer", "client_id", "client_secret", "cookie_secret"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("в ошибке не назван %s: %v", want, err)
		}
	}
}

func TestValidateCookieSecretLength(t *testing.T) {
	cases := []struct {
		name   string
		secret string
		ok     bool
	}{
		{"16 байт", "0123456789abcdef", true},
		{"24 байта", "0123456789abcdef01234567", true},
		{"32 байта", "0123456789abcdef0123456789abcdef", true},
		{"base64 от 32 байт", "TzRhb0hLcVJ2WGoyTG1QN3NEd0V5TjVjQmdVaXQ4az0=", true},
		{"base64url от 32 байт", "__________________________________________8=", true},
		{"короткий", "коротко", false},
		{"20 байт", "01234567890123456789", false},
		// openssl rand -base64 32 иногда выдаёт "+" или "/". Такую строку
		// oauth2-proxy не декодирует и падает на её длине — 44 байта.
		{"обычный base64 с плюсом и слешем", "//////////////////////////////////////////8=", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &Config{
				Server: "https://leauth.example.com",
				Name:   "srv-01",
				OAuth: OAuthConfig{
					Issuer:       "https://gitlab.example.com",
					ClientID:     "клиент",
					ClientSecret: "секрет",
					CookieSecret: c.secret,
				},
				Endpoints: []Endpoint{{
					Domain:   "docs.example.com",
					Listen:   8443,
					Upstream: "http://app:3000",
					OAuth:    &EndpointOAuth{},
				}},
			}

			err := cfg.Validate()
			if c.ok && err != nil {
				t.Errorf("секрет отвергнут: %v", err)
			}
			if !c.ok && err == nil {
				t.Error("секрет принят, хотя oauth2-proxy его не примет")
			}
		})
	}
}

// Порт oauth2-proxy занят изнутри контейнера, и совпадение с listen
// проявилось бы падением nginx или процесса на старте.
func TestValidateOAuthPortCollision(t *testing.T) {
	cfg := &Config{
		Server: "https://leauth.example.com",
		Name:   "srv-01",
		OAuth: OAuthConfig{
			Issuer:       "https://gitlab.example.com",
			ClientID:     "клиент",
			ClientSecret: "секрет",
			CookieSecret: "0123456789abcdef",
		},
		Endpoints: []Endpoint{
			{Domain: "docs.example.com", Listen: OAuthBasePort, Upstream: "http://app:3000", OAuth: &EndpointOAuth{}},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("ожидалась ошибка")
	}
	if !strings.Contains(err.Error(), "oauth2-proxy") {
		t.Errorf("ошибка не объясняет причину: %v", err)
	}
}

func TestValidateExternalURL(t *testing.T) {
	cfg := &Config{
		Server: "https://leauth.example.com",
		Name:   "srv-01",
		Endpoints: []Endpoint{
			{Domain: "docs.example.com", Listen: 8443, Upstream: "http://app:3000", ExternalURL: "docs.example.com"},
		},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "external_url") {
		t.Errorf("адрес без схемы должен отвергаться: %v", err)
	}
}

// Ошибка в skip_paths тихо открывает эндпоинт, поэтому проверки строгие.
func TestValidateSkipPaths(t *testing.T) {
	cases := map[string]struct {
		paths []string
		ok    bool
	}{
		"обычный префикс":   {[]string{"/api/"}, true},
		"без слеша":         {[]string{"api/"}, false},
		"корень":            {[]string{"/"}, false},
		"путь oauth2-proxy": {[]string{"/oauth2/callback"}, false},
		"точка с запятой":   {[]string{"/api/;return 200"}, false},
		"пробел":            {[]string{"/api/ x"}, false},
		"повтор":            {[]string{"/api/", "/api/"}, false},
		"несколько путей":   {[]string{"/api/", "/healthz"}, true},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := &Config{
				Server: "https://leauth.example.com",
				Name:   "srv-01",
				OAuth: OAuthConfig{
					Issuer:       "https://gitlab.example.com",
					ClientID:     "клиент",
					ClientSecret: "секрет",
					CookieSecret: "0123456789abcdef",
				},
				Endpoints: []Endpoint{{
					Domain:   "docs.example.com",
					Listen:   8443,
					Upstream: "http://app:3000",
					OAuth:    &EndpointOAuth{SkipPaths: c.paths},
				}},
			}

			err := cfg.Validate()
			if c.ok && err != nil {
				t.Errorf("путь отвергнут: %v", err)
			}
			if !c.ok && err == nil {
				t.Error("путь принят, хотя не должен")
			}
		})
	}
}
