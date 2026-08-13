package agent

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"leauth/internal/api"
	"leauth/internal/envsubst"
)

// Duration разбирает строки вида "1h".
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("длительность должна быть строкой: %w", err)
	}

	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("не разобрать длительность %q: %w", s, err)
	}

	*d = Duration(parsed)
	return nil
}

func (d Duration) Duration() time.Duration { return time.Duration(d) }

// OAuthConfig — реквизиты GitLab, общие для всех эндпоинтов прокси.
type OAuthConfig struct {
	Issuer       string `yaml:"issuer"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	CookieSecret string `yaml:"cookie_secret"`
	// AuthDomain включает общий вход: все закрытые эндпоинты входят через
	// один домен и обслуживаются одним процессом oauth2-proxy. В GitLab
	// тогда нужен один redirect URI на всю установку, и новый закрытый
	// домен не требует туда возвращаться.
	//
	// Пусто — режим по умолчанию: процесс на эндпоинт и свой redirect URI
	// у каждого домена. Подробности — в deploy/proxy/README.md.
	AuthDomain string `yaml:"auth_domain"`
}

// Shared отвечает, включён ли общий вход.
func (o OAuthConfig) Shared() bool { return o.AuthDomain != "" }

// EndpointOAuth включает авторизацию на эндпоинте. Пустой список групп
// пускает любого, кто вошёл в GitLab, поэтому важно отличать `oauth: {}`
// от отсутствующего блока — за это отвечает указатель в Endpoint.
type EndpointOAuth struct {
	Groups []string `yaml:"groups"`
	// SkipPaths — префиксы путей, которые проходят мимо авторизации.
	// Нужны там, где по одному адресу живут и страница для человека, и
	// машинный интерфейс: браузерный вход клиент с токеном не переживёт.
	SkipPaths []string `yaml:"skip_paths"`
}

// UpstreamAuth — реквизиты, с которыми прокси ходит на бэкенд. Нужны
// бэкендам с собственной basic-авторизацией: снаружи вход закрывает
// GitLab, а внутрь прокси заходит по паролю приложения. Пароль лучше
// подставлять из окружения, а не писать в конфиг открытым текстом.
type UpstreamAuth struct {
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

// Header возвращает готовое значение заголовка Authorization.
func (u UpstreamAuth) Header() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(u.User+":"+u.Password))
}

// Endpoint — один домен, который прокси закрывает TLS.
type Endpoint struct {
	Domain   string `yaml:"domain"`
	Listen   int    `yaml:"listen"`
	Upstream string `yaml:"upstream"`
	// UpstreamAuth подставляется в запрос к бэкенду вместо заголовка,
	// присланного клиентом.
	UpstreamAuth *UpstreamAuth `yaml:"upstream_auth"`
	// ExternalURL — адрес, по которому эндпоинт открывают снаружи, если
	// он отличается от domain:listen: балансировщик или проброс порта.
	ExternalURL string         `yaml:"external_url"`
	OAuth       *EndpointOAuth `yaml:"oauth"`
}

type Config struct {
	Server string `yaml:"server"`
	// Name — имя прокси в центре. По умолчанию имя хоста.
	Name string `yaml:"name"`
	// EnrollToken — общий токен приёма. Нужен только при первом запуске:
	// дальше прокси ходит с персональным токеном, который хранит в
	// cert_dir и который переживает пересоздание контейнера.
	EnrollToken string `yaml:"enroll_token"`
	CertDir     string `yaml:"cert_dir"`
	// Resolver — DNS для ленивого резолва апстримов внутри nginx.
	Resolver     string   `yaml:"resolver"`
	PollInterval Duration `yaml:"poll_interval"`
	// WildcardZones — зоны, на которые заказывается один сертификат
	// с *.<зона>. Все эндпоинты внутри зоны используют его, поэтому
	// CNAME прописывается один раз на зону.
	WildcardZones []string    `yaml:"wildcard_zones"`
	OAuth         OAuthConfig `yaml:"oauth"`
	Endpoints     []Endpoint  `yaml:"endpoints"`
}

func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("чтение конфига агента: %w", err)
	}

	expanded, err := envsubst.Expand(string(raw))
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("разбор конфига агента: %w", err)
	}

	if cfg.CertDir == "" {
		cfg.CertDir = "/etc/leauth/certs"
	}
	if cfg.Name == "" {
		// Имя хоста — то, что человек и так знает про этот сервер.
		host, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("не задан name и не удалось узнать имя хоста: %w", err)
		}
		cfg.Name = host
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = Duration(time.Hour)
	}
	if cfg.Resolver == "" {
		cfg.Resolver = DefaultResolver
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// ListenPorts — порты, которые займёт nginx, в порядке появления.
// Их и нужно опубликовать наружу: сам агент об этом позаботиться не может,
// публикацией занимается docker.
func (c *Config) ListenPorts() []int {
	var out []int
	seen := map[int]bool{}

	for _, e := range c.Endpoints {
		if !seen[e.Listen] {
			seen[e.Listen] = true
			out = append(out, e.Listen)
		}
	}
	return out
}

// Validate проверяет конфиг целиком и собирает все проблемы разом:
// человек, правящий agent.yaml, должен увидеть весь список, а не первую
// ошибку из десяти.
func (c *Config) Validate() error {
	var problems []string

	if c.Server == "" {
		problems = append(problems, "не задан server")
	} else if !strings.HasPrefix(c.Server, "https://") && !strings.HasPrefix(c.Server, "http://") {
		problems = append(problems, "server должен начинаться с https:// или http://")
	}

	// Имя проверяется тем же кодом, что и на центре: иначе прокси
	// поднялся бы и получил отказ в приёме только при первом запросе.
	name, err := api.ValidateClientName(c.Name)
	if err != nil {
		problems = append(problems, fmt.Sprintf("имя прокси %q: %v", c.Name, err))
	}
	c.Name = name

	if len(c.Endpoints) == 0 {
		problems = append(problems, "не задан ни один endpoint")
	}

	seenZone := map[string]bool{}
	for i, z := range c.WildcardZones {
		switch {
		case z == "":
			problems = append(problems, fmt.Sprintf("wildcard_zones[%d]: пустое имя зоны", i))
		case strings.HasPrefix(z, "*."):
			problems = append(problems, fmt.Sprintf(
				"wildcard_zones[%d]: зона пишется без звёздочки — %q вместо %q",
				i, strings.TrimPrefix(z, "*."), z))
		case seenZone[z]:
			problems = append(problems, fmt.Sprintf("wildcard_zones[%d]: зона %s повторяется", i, z))
		default:
			zone, err := api.ValidateDomain(z)
			if err != nil {
				problems = append(problems, fmt.Sprintf("wildcard_zones[%d]: %v", i, err))
			} else {
				c.WildcardZones[i] = zone
			}
		}
		seenZone[z] = true
	}

	// Домены различаются по SNI, поэтому на одном порту их может быть
	// сколько угодно. Занятые порты нужны дальше, чтобы поймать
	// пересечение с портами oauth2-proxy; хранится первый домен на порту
	// — только ради текста ошибки.
	portDomain := map[int]string{}
	seenPair := map[string]bool{}

	for i, e := range c.Endpoints {
		where := fmt.Sprintf("endpoint %d (%s)", i, e.Domain)

		// Домен уходит в server_name конфига nginx, поэтому проверяется
		// его форма, а не только непустота: пробел или точка с запятой
		// в имени дописали бы в конфиг произвольные директивы.
		domain, err := api.ValidateDomain(e.Domain)
		if err != nil {
			problems = append(problems, where+": "+err.Error())
		}
		c.Endpoints[i].Domain = domain

		if e.Listen < 1 || e.Listen > 65535 {
			problems = append(problems, fmt.Sprintf("%s: некорректный порт %d", where, e.Listen))
		}
		problems = append(problems, upstreamProblems(where, e.Upstream)...)

		if e.ExternalURL != "" {
			if !strings.HasPrefix(e.ExternalURL, "https://") {
				problems = append(problems, where+": external_url должен начинаться с https://")
			} else if _, err := url.Parse(e.ExternalURL); err != nil {
				problems = append(problems, fmt.Sprintf("%s: не разобрать external_url: %v", where, err))
			} else if strings.ContainsAny(e.ExternalURL, nginxUnsafe) {
				problems = append(problems, where+": недопустимые символы в external_url")
			}
		}
		if e.OAuth != nil {
			problems = append(problems, skipPathProblems(where, e.OAuth.SkipPaths)...)
		}
		if u := e.UpstreamAuth; u != nil {
			switch {
			case u.User == "":
				problems = append(problems, where+": upstream_auth без user")
			case strings.Contains(u.User, ":"):
				problems = append(problems, where+": двоеточие в upstream_auth.user делит логин и пароль")
			case u.Password == "":
				problems = append(problems, where+": upstream_auth без password")
			}
		}

		pair := fmt.Sprintf("%s:%d", c.Endpoints[i].Domain, e.Listen)
		if seenPair[pair] {
			problems = append(problems, fmt.Sprintf("%s: домен %s на порту %d уже объявлен", where, e.Domain, e.Listen))
		}

		seenPair[pair] = true
		if _, ok := portDomain[e.Listen]; !ok {
			portDomain[e.Listen] = e.Domain
		}
	}

	problems = append(problems, c.oauthProblems(portDomain)...)

	if len(problems) > 0 {
		return errors.New("конфиг агента: " + strings.Join(problems, "; "))
	}
	return nil
}

// nginxUnsafe — символы, которыми в конфиге nginx кончается директива или
// начинается подстановка переменной. Ни одному значению из agent.yaml они
// не нужны, а попав в шаблон, дописали бы в конфиг что угодно.
const nginxUnsafe = " \t\r\n\"'{};$\\"

// upstreamProblems проверяет адрес бэкенда: он попадает в proxy_pass,
// поэтому мало убедиться в схеме — нужно, чтобы адрес разбирался и не
// содержал символов, значимых для конфига nginx.
func upstreamProblems(where, upstream string) []string {
	if !strings.HasPrefix(upstream, "http://") && !strings.HasPrefix(upstream, "https://") {
		return []string{where + ": upstream должен начинаться с http:// или https://"}
	}
	if strings.ContainsAny(upstream, nginxUnsafe) {
		return []string{fmt.Sprintf("%s: недопустимые символы в upstream %q", where, upstream)}
	}

	u, err := url.Parse(upstream)
	if err != nil {
		return []string{fmt.Sprintf("%s: не разобрать upstream %q: %v", where, upstream, err)}
	}
	if u.Host == "" {
		return []string{fmt.Sprintf("%s: в upstream %q нет адреса бэкенда", where, upstream)}
	}
	// Путь дописывается из $request_uri, поэтому свой путь в upstream
	// молча потерялся бы — лучше сказать об этом на старте.
	if u.Path != "" && u.Path != "/" {
		return []string{fmt.Sprintf(
			"%s: путь %q в upstream не поддерживается — запрос уходит на бэкенд как есть", where, u.Path)}
	}
	return nil
}

// skipPathProblems проверяет пути, выведенные из-под авторизации. Ошибка
// здесь тихо открывает эндпоинт, поэтому проверки строгие: "/" открыл бы
// его целиком, а спецсимволы могли бы дописать в конфиг nginx что угодно.
func skipPathProblems(where string, paths []string) []string {
	var problems []string
	seen := map[string]bool{}

	for _, p := range paths {
		switch {
		case !strings.HasPrefix(p, "/"):
			problems = append(problems, fmt.Sprintf("%s: skip_paths %q должен начинаться со слеша", where, p))
		case p == "/":
			problems = append(problems, where+`: skip_paths "/" снял бы авторизацию со всего эндпоинта`)
		case strings.HasPrefix(p, "/oauth2/"):
			problems = append(problems, fmt.Sprintf(
				"%s: путь %q занят самим oauth2-proxy", where, p))
		case strings.ContainsAny(p, nginxUnsafe):
			problems = append(problems, fmt.Sprintf("%s: недопустимые символы в skip_paths %q", where, p))
		case seen[p]:
			problems = append(problems, fmt.Sprintf("%s: skip_paths %q повторяется", where, p))
		}
		seen[p] = true
	}
	return problems
}

// oauthProblems проверяет то, без чего авторизация молча не заработает.
// Конфиг с блоком oauth, но без реквизитов GitLab, поднял бы открытый
// прокси там, где ожидался закрытый, поэтому это ошибка запуска.
func (c *Config) oauthProblems(portDomain map[int]string) []string {
	if !c.hasOAuth() {
		return nil
	}

	var problems []string

	// Проверяется до OAuthInstances: при негодном общем входе список
	// процессов пуст, и остальные проверки молча прошли бы мимо.
	problems = append(problems, c.sharedOAuthProblems()...)

	if c.OAuth.Issuer == "" {
		problems = append(problems, "есть эндпоинты с oauth, но не задан oauth.issuer")
	} else if !strings.HasPrefix(c.OAuth.Issuer, "https://") {
		problems = append(problems, "oauth.issuer должен начинаться с https://")
	}
	if c.OAuth.ClientID == "" {
		problems = append(problems, "есть эндпоинты с oauth, но не задан oauth.client_id")
	}
	if c.OAuth.ClientSecret == "" {
		problems = append(problems, "есть эндпоинты с oauth, но не задан oauth.client_secret")
	}
	if c.OAuth.CookieSecret == "" {
		problems = append(problems, "есть эндпоинты с oauth, но не задан oauth.cookie_secret")
	} else if !validCookieSecret(c.OAuth.CookieSecret) {
		problems = append(problems,
			"oauth.cookie_secret должен быть 16, 24 или 32 байта — сгенерируйте: "+
				"openssl rand -base64 32 | tr -- '+/' '-_'")
	}

	for _, inst := range c.OAuthInstances() {
		if domain, ok := portDomain[inst.Port]; ok {
			problems = append(problems, fmt.Sprintf(
				"порт %d занят доменом %s, но нужен oauth2-proxy для %s",
				inst.Port, domain, inst.Endpoint.Domain))
		}
	}

	return problems
}

// sharedOAuthProblems проверяет общий вход. Ошибка здесь не открывает
// доступ — она его ломает: вход, который не возвращает человека обратно,
// или cookie, невидимая закрытому домену, выглядят как бесконечный цикл
// логина, и разбираться в этом по логам oauth2-proxy тяжело.
func (c *Config) sharedOAuthProblems() []string {
	if !c.OAuth.Shared() {
		return nil
	}

	domain, err := api.ValidateDomain(c.OAuth.AuthDomain)
	if err != nil {
		return []string{fmt.Sprintf("oauth.auth_domain: %v", err)}
	}
	c.OAuth.AuthDomain = domain

	var problems []string

	// На auth_domain живут /oauth2/start и /oauth2/callback, поэтому он
	// должен быть обычным эндпоинтом: со своим сертификатом и портом.
	if _, ok := c.endpointFor(domain); !ok {
		problems = append(problems, fmt.Sprintf(
			"oauth.auth_domain %s должен быть объявлен и в endpoints — на нём происходит вход", domain))
	}

	// Одна сессия на все домены возможна, только пока у них есть общий
	// родительский домен: cookie шире него не ставится.
	if cookie := c.cookieDomain(); cookie == "" {
		names := []string{domain}
		for _, e := range c.closedEndpoints() {
			names = append(names, e.Domain)
		}
		problems = append(problems, fmt.Sprintf(
			"общий вход невозможен: у %v нет общего домена, и одной сессионной cookie на всех не хватит — "+
				"уберите oauth.auth_domain либо разнесите домены по разным прокси", names))
	}

	return problems
}

// validCookieSecret повторяет encryption.SecretBytes из oauth2-proxy:
// секрет шифрует сессионную cookie, поэтому длина должна подходить AES.
//
// Декодируется только base64url без выравнивания; при неудаче строка
// берётся как есть. Обычный base64 с "+" и "/" в url-алфавит не
// укладывается, поэтому вывод `openssl rand -base64 32` до процесса
// доходит сырыми 44 символами и тот отказывается стартовать.
func validCookieSecret(s string) bool {
	sizes := []int{16, 24, 32}

	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err == nil && slices.Contains(sizes, len(raw)) {
		return true
	}
	// Декодировать не вышло или вышла негодная длина — oauth2-proxy
	// в этом месте берёт строку как есть.
	return slices.Contains(sizes, len(s))
}
