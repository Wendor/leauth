package server

import (
	"crypto/subtle"
	_ "embed"
	"html/template"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"leauth/internal/api"
	"leauth/internal/server/store"
)

//go:embed status.html
var statusHTML string

var statusTmpl = template.Must(template.New("status").Parse(statusHTML))

// StatusPage — read-only страница для человека: какой CNAME прописать,
// в каком состоянии домен, когда истекает сертификат.
type StatusPage struct {
	store    *store.Store
	user     string
	password string
}

func NewStatusPage(s *store.Store, user, password string) *StatusPage {
	return &StatusPage{store: s, user: user, password: password}
}

func (p *StatusPage) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /", p.handle)
}

type statusRow struct {
	Name        string
	Wildcard    bool
	Status      api.DomainStatus
	CNAMEName   string
	CNAMETarget string
	NotAfter    string
	Serial      string
	LastError   string
	// Clients — прокси, заявившие домен. Пустой список означает, что
	// домен больше никто не обслуживает и он не продлевается.
	Clients []string
}

func (p *StatusPage) authorized(r *http.Request) bool {
	user, password, ok := r.BasicAuth()
	if !ok {
		return false
	}

	// Сравниваются хеши: длина одинаковая, поэтому сравнение не выдаёт
	// длину пароля временем работы.
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(p.user)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(HashToken(password)), []byte(HashToken(p.password))) == 1

	return userOK && passOK
}

// authHeader — заголовок о вошедшем в том виде, в каком его получает
// бэкенд за прокси.
type authHeader struct {
	Name  string
	Value string
}

// authHeaderPrefix — префикс заголовков, которые прокси ставит после
// проверки сессии.
const authHeaderPrefix = "X-Auth-Request-"

// authOrder задаёт начало списка. Остальные заголовки с тем же префиксом
// идут следом по алфавиту: набор задаётся конфигом прокси и со временем
// может отличаться от того, что известно центру.
var authOrder = []string{"User", "Email", "Groups"}

// authHeaders собирает всё, что прокси рассказал о пришедшем. Это
// справка, а не проверка доступа: пускает на страницу пароль
// администратора, а заголовки подставляет прокси — центр, до которого
// достучались в обход прокси, увидит здесь что угодно.
func authHeaders(h http.Header) []authHeader {
	var out []authHeader

	add := func(name, value string) {
		if value != "" {
			out = append(out, authHeader{Name: name, Value: value})
		}
	}

	seen := map[string]bool{}
	for _, suffix := range authOrder {
		name := authHeaderPrefix + suffix
		seen[name] = true
		add(name, h.Get(name))
	}

	var rest []string
	for name := range h {
		if strings.HasPrefix(name, authHeaderPrefix) && !seen[name] {
			rest = append(rest, name)
		}
	}
	slices.Sort(rest)

	for _, name := range rest {
		add(name, h.Get(name))
	}
	return out
}

func (p *StatusPage) handle(w http.ResponseWriter, r *http.Request) {
	if !p.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Basic realm="leauth"`)
		http.Error(w, "требуется авторизация", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()

	domains, err := p.store.ListDomains(ctx)
	if err != nil {
		http.Error(w, "не удалось прочитать список доменов", http.StatusInternalServerError)
		slog.Error("страница статуса", "ошибка", err)
		return
	}

	rows := make([]statusRow, 0, len(domains))
	for _, d := range domains {
		row := statusRow{
			Name:        d.Name,
			Wildcard:    d.Wildcard,
			Status:      d.Status,
			CNAMEName:   "_acme-challenge." + d.Name,
			CNAMETarget: d.Account.FullDomain,
			LastError:   d.LastError,
		}

		if cert, err := p.store.LatestCertMeta(ctx, d.ID); err == nil {
			row.Serial = cert.Serial
			row.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
		}

		if clients, err := p.store.ClientsForDomain(ctx, d.ID); err == nil {
			row.Clients = clients
		}

		rows = append(rows, row)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	err = statusTmpl.Execute(w, map[string]any{
		"Domains": rows,
		"Now":     time.Now().UTC().Format(time.RFC3339),
		"Auth":    authHeaders(r.Header),
	})
	if err != nil {
		slog.Error("рендер страницы статуса", "ошибка", err)
	}
}
