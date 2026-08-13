package agent

import (
	"slices"
	"strings"
	"testing"
)

// Три состояния эндпоинта различаются наличием блока oauth, а YAML
// `oauth: {}` обязан отличаться от его отсутствия.
func TestLoadConfigOAuthStates(t *testing.T) {
	t.Setenv("LEAUTH_TOKEN", "токен-1")

	cfg, err := LoadConfig(writeAgentConfig(t, `
server: https://leauth.example.com
token: ${LEAUTH_TOKEN}
oauth:
  issuer: https://gitlab.example.com
  client_id: клиент
  client_secret: секрет
  cookie_secret: 0123456789abcdef
endpoints:
  - domain: docs.example.com
    listen: 8443
    upstream: http://app:3000
    oauth:
      groups: [platform/backend, platform/sre]
  - domain: wiki.example.com
    listen: 9443
    upstream: http://wiki:8080
    oauth: {}
  - domain: public.example.com
    listen: 7443
    upstream: http://static:80
`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if got := cfg.Endpoints[0].OAuth.Groups; !slices.Equal(got, []string{"platform/backend", "platform/sre"}) {
		t.Errorf("группы = %v", got)
	}
	if cfg.Endpoints[1].OAuth == nil {
		t.Error("oauth: {} должен включать авторизацию без ограничения по группам")
	} else if len(cfg.Endpoints[1].OAuth.Groups) != 0 {
		t.Error("oauth: {} не должен добавлять групп")
	}
	if cfg.Endpoints[2].OAuth != nil {
		t.Error("эндпоинт без блока oauth должен остаться открытым")
	}
}

func TestOAuthInstancesNumberPorts(t *testing.T) {
	cfg := &Config{Endpoints: []Endpoint{
		{Domain: "a.example.com", Listen: 8443, OAuth: &EndpointOAuth{}},
		{Domain: "open.example.com", Listen: 8444},
		{Domain: "b.example.com", Listen: 8445, OAuth: &EndpointOAuth{}},
	}}

	inst := cfg.OAuthInstances()
	if len(inst) != 2 {
		t.Fatalf("инстансов: %d", len(inst))
	}
	if inst[0].Port != OAuthBasePort || inst[1].Port != OAuthBasePort+1 {
		t.Errorf("порты = %d, %d", inst[0].Port, inst[1].Port)
	}
	if inst[1].Endpoint.Domain != "b.example.com" {
		t.Errorf("открытый эндпоинт не должен занимать порт: %s", inst[1].Endpoint.Domain)
	}
}

func TestRedirectURL(t *testing.T) {
	cases := []struct {
		name string
		e    Endpoint
		want string
	}{
		{
			name: "порт добавляется",
			e:    Endpoint{Domain: "docs.example.com", Listen: 8443},
			want: "https://docs.example.com:8443/oauth2/callback",
		},
		{
			name: "443 опускается",
			e:    Endpoint{Domain: "docs.example.com", Listen: 443},
			want: "https://docs.example.com/oauth2/callback",
		},
		{
			name: "external_url перекрывает вычисленное",
			e:    Endpoint{Domain: "wiki.example.com", Listen: 9443, ExternalURL: "https://wiki.example.com"},
			want: "https://wiki.example.com/oauth2/callback",
		},
		{
			name: "хвостовой слеш не удваивается",
			e:    Endpoint{Domain: "wiki.example.com", Listen: 9443, ExternalURL: "https://wiki.example.com/"},
			want: "https://wiki.example.com/oauth2/callback",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.e.RedirectURL(); got != c.want {
				t.Errorf("redirect = %q, ожидалось %q", got, c.want)
			}
		})
	}
}

// Секреты уходят в окружение процесса: в аргументах их видно в ps.
func TestOAuthArgsAndEnv(t *testing.T) {
	endpoint := Endpoint{
		Domain:   "docs.example.com",
		Listen:   8443,
		Upstream: "http://app:3000",
		OAuth:    &EndpointOAuth{Groups: []string{"platform/backend", "platform/sre"}},
	}
	cfg := &Config{
		OAuth: OAuthConfig{
			Issuer:       "https://gitlab.example.com",
			ClientID:     "клиент",
			ClientSecret: "секрет",
			CookieSecret: "0123456789abcdef",
		},
		Endpoints: []Endpoint{endpoint},
	}
	oauth := cfg.OAuth
	inst := OAuthInstance{Endpoint: endpoint, Port: 4180}

	args := inst.Args(cfg)
	joined := strings.Join(args, " ")

	for _, want := range []string{
		"--provider=gitlab",
		"--oidc-issuer-url=https://gitlab.example.com",
		"--redirect-url=https://docs.example.com:8443/oauth2/callback",
		"--http-address=127.0.0.1:4180",
		"--set-xauthrequest=true",
		"--reverse-proxy=true",
		"--trusted-proxy-ip=127.0.0.1/32",
		"--gitlab-group=platform/backend",
		"--gitlab-group=platform/sre",
	} {
		if !slices.Contains(args, want) {
			t.Errorf("нет аргумента %s в: %s", want, joined)
		}
	}

	for _, secret := range []string{"секрет", "0123456789abcdef", "клиент"} {
		if strings.Contains(joined, secret) {
			t.Errorf("секрет попал в аргументы: %s", joined)
		}
	}

	env := inst.Env(oauth)
	for _, want := range []string{
		"OAUTH2_PROXY_CLIENT_ID=клиент",
		"OAUTH2_PROXY_CLIENT_SECRET=секрет",
		"OAUTH2_PROXY_COOKIE_SECRET=0123456789abcdef",
	} {
		if !slices.Contains(env, want) {
			t.Errorf("нет переменной %s в %v", want, env)
		}
	}
}

// Без групп oauth2-proxy пускает любого, кто вошёл в GitLab.
func TestOAuthArgsWithoutGroups(t *testing.T) {
	endpoint := Endpoint{Domain: "wiki.example.com", Listen: 443, OAuth: &EndpointOAuth{}}
	inst := OAuthInstance{Endpoint: endpoint, Port: 4180}
	cfg := &Config{
		OAuth:     OAuthConfig{Issuer: "https://gitlab.example.com"},
		Endpoints: []Endpoint{endpoint},
	}

	for _, a := range inst.Args(cfg) {
		if strings.HasPrefix(a, "--gitlab-group=") {
			t.Errorf("лишнее ограничение по группам: %s", a)
		}
	}
}

// sharedConfig — установка с общим входом: вход на auth.example.com,
// два закрытых домена рядом.
func sharedConfig() *Config {
	return &Config{
		Server: "https://c", Name: "srv-01", CertDir: "/certs",
		OAuth: OAuthConfig{
			Issuer:       "https://gitlab.example.com",
			ClientID:     "клиент",
			ClientSecret: "секрет",
			CookieSecret: "0123456789abcdef",
			AuthDomain:   "auth.example.com",
		},
		Endpoints: []Endpoint{
			{Domain: "auth.example.com", Listen: 8443, Upstream: "http://static:80"},
			{Domain: "docs.example.com", Listen: 8443, Upstream: "http://docs:8080",
				OAuth: &EndpointOAuth{Groups: []string{"platform/backend"}}},
			{Domain: "wiki.example.com", Listen: 8443, Upstream: "http://wiki:8080",
				OAuth: &EndpointOAuth{}},
		},
	}
}

// При общем входе процесс один на всю установку, а redirect URI —
// на домене входа: именно ради этого режим и существует.
func TestSharedOAuthSingleInstance(t *testing.T) {
	cfg := sharedConfig()

	instances := cfg.OAuthInstances()
	if len(instances) != 1 {
		t.Fatalf("процессов oauth2-proxy: %d, при общем входе ожидался 1", len(instances))
	}
	inst := instances[0]

	if !inst.Shared {
		t.Error("процесс не помечен общим")
	}
	if got := inst.Endpoint.RedirectURL(); got != "https://auth.example.com:8443/oauth2/callback" {
		t.Errorf("redirect URI = %q", got)
	}
	if inst.Port != OAuthBasePort {
		t.Errorf("порт = %d, ожидался %d", inst.Port, OAuthBasePort)
	}
}

func TestSharedOAuthArgs(t *testing.T) {
	cfg := sharedConfig()
	args := cfg.OAuthInstances()[0].Args(cfg)

	for _, want := range []string{
		// Сессия видна всем закрытым доменам.
		"--cookie-domain=example.com",
		// Возврат разрешён только на объявленные адреса, вместе с портом.
		"--whitelist-domain=docs.example.com:8443",
		"--whitelist-domain=wiki.example.com:8443",
		"--whitelist-domain=auth.example.com:8443",
	} {
		if !slices.Contains(args, want) {
			t.Errorf("нет аргумента %s в %v", want, args)
		}
	}

	// Группы проверяются на запросе: на процессе они действовали бы
	// сразу на все домены.
	for _, a := range args {
		if strings.HasPrefix(a, "--gitlab-group=") {
			t.Errorf("группы остались на процессе: %s", a)
		}
	}
}

// Порт по умолчанию в адресе возврата не указывается: oauth2-proxy
// сравнивает пустой порт с пустым.
func TestSharedOAuthReturnAddressOmitsDefaultPort(t *testing.T) {
	cfg := sharedConfig()
	cfg.Endpoints[1].Listen = 443
	cfg.Endpoints[1].ExternalURL = ""

	if got := cfg.returnAddresses(); !slices.Contains(got, "docs.example.com") {
		t.Errorf("адреса возврата = %v, ожидался docs.example.com без порта", got)
	}
}

// external_url задаёт адрес, по которому эндпоинт открывают снаружи, —
// возвращать нужно именно туда.
func TestSharedOAuthReturnAddressUsesExternalURL(t *testing.T) {
	cfg := sharedConfig()
	cfg.Endpoints[1].ExternalURL = "https://docs.example.com:9443"

	got := cfg.returnAddresses()
	if !slices.Contains(got, "docs.example.com:9443") {
		t.Errorf("адреса возврата = %v, ожидался docs.example.com:9443", got)
	}
	if slices.Contains(got, "docs.example.com:8443") {
		t.Errorf("внутренний порт попал в адреса возврата: %v", got)
	}
}

func TestAllowedGroupsQuery(t *testing.T) {
	cases := []struct {
		name string
		e    Endpoint
		want string
	}{
		{"без блока oauth", Endpoint{}, ""},
		{"пустой блок пускает любого вошедшего", Endpoint{OAuth: &EndpointOAuth{}}, ""},
		{
			"слеш в имени группы кодируется",
			Endpoint{OAuth: &EndpointOAuth{Groups: []string{"platform/backend"}}},
			"?allowed_groups=platform%2Fbackend",
		},
		{
			"несколько групп — через запятую",
			Endpoint{OAuth: &EndpointOAuth{Groups: []string{"a", "b/c"}}},
			"?allowed_groups=a,b%2Fc",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.e.AllowedGroupsQuery(); got != c.want {
				t.Errorf("query = %q, ожидалось %q", got, c.want)
			}
		})
	}
}

func TestCommonDomainSuffix(t *testing.T) {
	cases := []struct {
		names []string
		want  string
	}{
		{[]string{"auth.example.com", "docs.example.com"}, "example.com"},
		{[]string{"auth.example.com", "docs.a.example.com", "wiki.b.example.com"}, "example.com"},
		{[]string{"example.com", "docs.example.com"}, "example.com"},
		{[]string{"auth.a.example.com", "docs.a.example.com"}, "a.example.com"},
		// Разные зоны: одной cookie на всех не хватит.
		{[]string{"auth.example.com", "docs.other.net"}, ""},
		// Общий хвост в один уровень — это домен верхнего уровня.
		{[]string{"auth.example.com", "docs.other.com"}, ""},
		{nil, ""},
	}

	for _, c := range cases {
		if got := commonDomainSuffix(c.names); got != c.want {
			t.Errorf("commonDomainSuffix(%v) = %q, ожидалось %q", c.names, got, c.want)
		}
	}
}
