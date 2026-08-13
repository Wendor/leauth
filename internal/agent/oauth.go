package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

// OAuthBasePort — первый порт, который занимают процессы oauth2-proxy.
// Они слушают только петлевой интерфейс внутри контейнера.
const OAuthBasePort = 4180

// oauth2ProxyBinary кладётся в образ прокси из официального образа.
const oauth2ProxyBinary = "oauth2-proxy"

// OAuthInstance — один процесс oauth2-proxy.
//
// В режиме по умолчанию процесс нужен на каждый закрытый эндпоинт:
// redirect-url задаётся на процесс, а он привязан к домену. При общем
// входе процесс один на всю установку — вход происходит на auth_domain,
// а куда вернуть человека, задаётся на каждом запросе.
type OAuthInstance struct {
	// Endpoint — эндпоинт, на котором живёт вход: при общем входе это
	// auth_domain, иначе сам закрытый эндпоинт.
	Endpoint Endpoint
	Port     int
	// Shared — процесс обслуживает все закрытые эндпоинты сразу.
	// Проверка групп тогда идёт не на процессе, а на запросе.
	Shared bool
}

// OAuthInstances перечисляет процессы oauth2-proxy. Порты вычисляются
// здесь и используются как при запуске процессов, так и при рендере
// nginx, поэтому разъехаться они не могут.
func (c *Config) OAuthInstances() []OAuthInstance {
	if !c.hasOAuth() {
		return nil
	}

	if c.OAuth.Shared() {
		// Вход живёт на auth_domain, поэтому и redirect-url берётся от
		// его эндпоинта. Валидация конфига гарантирует, что он объявлен.
		e, ok := c.endpointFor(c.OAuth.AuthDomain)
		if !ok {
			return nil
		}
		return []OAuthInstance{{Endpoint: e, Port: OAuthBasePort, Shared: true}}
	}

	var out []OAuthInstance
	for _, e := range c.Endpoints {
		if e.OAuth != nil {
			out = append(out, OAuthInstance{Endpoint: e, Port: OAuthBasePort + len(out)})
		}
	}
	return out
}

// hasOAuth — есть ли хоть один закрытый эндпоинт.
func (c *Config) hasOAuth() bool {
	return slices.ContainsFunc(c.Endpoints, func(e Endpoint) bool { return e.OAuth != nil })
}

// endpointFor возвращает первый эндпоинт домена. Домен может быть
// объявлен на нескольких портах; вход живёт на том, что объявлен первым.
func (c *Config) endpointFor(domain string) (Endpoint, bool) {
	for _, e := range c.Endpoints {
		if e.Domain == domain {
			return e, true
		}
	}
	return Endpoint{}, false
}

// closedEndpoints — эндпоинты с авторизацией.
func (c *Config) closedEndpoints() []Endpoint {
	var out []Endpoint
	for _, e := range c.Endpoints {
		if e.OAuth != nil {
			out = append(out, e)
		}
	}
	return out
}

// AllowedGroupsQuery — параметры запроса к /oauth2/auth, ограничивающие
// доступ группами GitLab. Пустой список групп пускает любого вошедшего.
//
// При общем входе проверку групп нельзя держать на процессе — он один на
// все домены, — поэтому она задаётся на каждом подзапросе. oauth2-proxy
// сверяет группы точным совпадением и отвечает 403, а не 401: иначе
// подзапрос увёл бы человека на повторный вход по кругу.
func (e Endpoint) AllowedGroupsQuery() string {
	if e.OAuth == nil || len(e.OAuth.Groups) == 0 {
		return ""
	}

	escaped := make([]string, 0, len(e.OAuth.Groups))
	for _, g := range e.OAuth.Groups {
		escaped = append(escaped, url.QueryEscape(g))
	}
	return "?allowed_groups=" + strings.Join(escaped, ",")
}

// ExternalBase — адрес, по которому пользователь открывает эндпоинт.
func (e Endpoint) ExternalBase() string {
	if e.ExternalURL != "" {
		return strings.TrimRight(e.ExternalURL, "/")
	}
	if e.Listen == 443 {
		return "https://" + e.Domain
	}
	return fmt.Sprintf("https://%s:%d", e.Domain, e.Listen)
}

// RedirectURL должен побайтно совпадать с записанным в приложении GitLab.
func (e Endpoint) RedirectURL() string {
	return e.ExternalBase() + "/oauth2/callback"
}

// Args собирает командную строку. Секретов здесь нет намеренно: аргументы
// видны в ps внутри контейнера, поэтому реквизиты уходят через Env.
func (i OAuthInstance) Args(c *Config) []string {
	o := c.OAuth

	args := []string{
		"--provider=gitlab",
		"--oidc-issuer-url=" + o.Issuer,
		"--redirect-url=" + i.Endpoint.RedirectURL(),
		"--http-address=127.0.0.1:" + strconv.Itoa(i.Port),
		"--scope=openid profile email",
		// Проверку выполняет группа, а не домен почты.
		"--email-domain=*",
		// nginx проксирует /oauth2/ и шлёт auth_request, поэтому нужны
		// заголовки X-Auth-Request-* и доверие к X-Forwarded-*.
		"--set-xauthrequest=true",
		"--reverse-proxy=true",
		// Заголовкам X-Forwarded-* верим только от nginx, который стоит
		// на том же localhost. Иначе их подставляет кто угодно снаружи:
		// адрес в логах перестаёт что-либо значить, а вместе с хостом
		// клиент влияет и на то, каким oauth2-proxy видит запрос.
		"--trusted-proxy-ip=127.0.0.1/32",
		"--trusted-proxy-ip=::1/128",
		// Промежуточная страница «войти через GitLab» не нужна.
		"--skip-provider-button=true",
		"--cookie-secure=true",
	}

	if !i.Shared {
		// Процесс обслуживает один домен, поэтому группы проверяются им же.
		for _, g := range i.Endpoint.OAuth.Groups {
			args = append(args, "--gitlab-group="+g)
		}
		return args
	}

	// Общий вход. Сессия обязана быть видна всем закрытым доменам, иначе
	// вход на auth_domain ничего им не даёт: cookie ставится на общий
	// родительский домен.
	args = append(args, "--cookie-domain="+c.cookieDomain())

	// Вернуться после входа можно только на объявленные адреса — иначе
	// параметром rd человека увели бы куда угодно. Адреса точные, вместе
	// с портом: oauth2-proxy сверяет и его.
	for _, addr := range c.returnAddresses() {
		args = append(args, "--whitelist-domain="+addr)
	}

	// --gitlab-group здесь нет намеренно: он бы действовал на все домены
	// сразу. Группы проверяются на каждом подзапросе, см. AllowedGroupsQuery.
	return args
}

// returnAddresses — адреса, на которые разрешено возвращать человека
// после входа: по одному на закрытый эндпоинт плюс сам домен входа,
// в форме host[:port]. Порт значим: oauth2-proxy сверяет и его.
func (c *Config) returnAddresses() []string {
	endpoints := c.closedEndpoints()
	if auth, ok := c.endpointFor(c.OAuth.AuthDomain); ok {
		endpoints = append(endpoints, auth)
	}

	var out []string
	seen := map[string]bool{}

	for _, e := range endpoints {
		addr := returnAddress(e)
		if !seen[addr] {
			seen[addr] = true
			out = append(out, addr)
		}
	}
	return out
}

// returnAddress — host[:port] эндпоинта в том виде, в каком его видит
// браузер. Порт по умолчанию опускается: oauth2-proxy сравнивает пустой
// порт с пустым.
func returnAddress(e Endpoint) string {
	if ext := e.ExternalURL; ext != "" {
		if u, err := url.Parse(ext); err == nil && u.Host != "" {
			return u.Host
		}
	}
	if e.Listen == 443 {
		return e.Domain
	}
	return fmt.Sprintf("%s:%d", e.Domain, e.Listen)
}

// cookieDomain — самый длинный доменный суффикс, общий для входа и всех
// закрытых эндпоинтов. Именно на него ставится сессионная cookie: шире
// — отдали бы её посторонним, уже — не увидел бы кто-то из своих.
func (c *Config) cookieDomain() string {
	names := []string{c.OAuth.AuthDomain}
	for _, e := range c.closedEndpoints() {
		names = append(names, e.Domain)
	}
	return commonDomainSuffix(names)
}

// commonDomainSuffix возвращает общий хвост имён по меткам. Пустая строка
// означает, что общего домена нет и одной cookie на всех не хватит.
func commonDomainSuffix(names []string) string {
	if len(names) == 0 {
		return ""
	}

	common := labelsOf(names[0])
	for _, name := range names[1:] {
		labels := labelsOf(name)

		n := min(len(common), len(labels))
		for n > 0 && common[len(common)-n] != labels[len(labels)-n] {
			n--
		}
		common = common[len(common)-n:]
	}

	// Одна метка — это домен верхнего уровня: cookie на ".com" не ставят.
	if len(common) < 2 {
		return ""
	}
	return strings.Join(common, ".")
}

func labelsOf(name string) []string {
	return strings.Split(strings.TrimSuffix(name, "."), ".")
}

// Env передаёт реквизиты через окружение процесса.
func (i OAuthInstance) Env(o OAuthConfig) []string {
	return []string{
		"OAUTH2_PROXY_CLIENT_ID=" + o.ClientID,
		"OAUTH2_PROXY_CLIENT_SECRET=" + o.ClientSecret,
		"OAUTH2_PROXY_COOKIE_SECRET=" + o.CookieSecret,
	}
}

// StartOAuthProxies поднимает процессы oauth2-proxy: по одному на
// закрытый эндпоинт или один общий, если задан auth_domain.
// Процессы живут, пока жив агент.
func StartOAuthProxies(ctx context.Context, cfg *Config) {
	for _, inst := range cfg.OAuthInstances() {
		// Несовпадение с приложением GitLab — самая частая ошибка
		// развёртывания, поэтому итоговый адрес видно в логе.
		if inst.Shared {
			slog.Info("запускается oauth2-proxy — общий вход на все закрытые эндпоинты",
				"домен входа", inst.Endpoint.Domain,
				"порт", inst.Port,
				"redirect_uri", inst.Endpoint.RedirectURL(),
				"cookie", cfg.cookieDomain(),
				"возврат разрешён на", cfg.returnAddresses())
		} else {
			slog.Info("запускается oauth2-proxy",
				"домен", inst.Endpoint.Domain,
				"порт", inst.Port,
				"redirect_uri", inst.Endpoint.RedirectURL(),
				"группы", inst.Endpoint.OAuth.Groups)
		}

		go superviseOAuth(ctx, inst, cfg)
	}
}

// superviseOAuth перезапускает процесс: oauth2-proxy завершается с
// ошибкой, если GitLab недоступен в момент OIDC discovery, и без
// перезапуска прокси остался бы без авторизации до ручного вмешательства.
func superviseOAuth(ctx context.Context, inst OAuthInstance, cfg *Config) {
	const (
		firstDelay = time.Second
		maxDelay   = time.Minute
		// Дольше этого — процесс считается поднявшимся, и пауза
		// сбрасывается: иначе редкие падения копили бы задержку.
		healthy = time.Minute
	)

	delay := firstDelay

	for ctx.Err() == nil {
		cmd := exec.CommandContext(ctx, oauth2ProxyBinary, inst.Args(cfg)...)
		cmd.Env = append(os.Environ(), inst.Env(cfg.OAuth)...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		started := time.Now()
		err := cmd.Run()

		if ctx.Err() != nil {
			return
		}

		slog.Error("oauth2-proxy завершился",
			"домен", inst.Endpoint.Domain,
			"ошибка", err,
			"проработал", time.Since(started).Round(time.Second),
			"перезапуск через", delay)

		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}

		if time.Since(started) > healthy {
			delay = firstDelay
		} else if delay < maxDelay {
			delay = min(2*delay, maxDelay)
		}
	}
}
