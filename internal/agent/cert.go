package agent

import (
	"strings"

	"leauth/internal/api"
)

// Certificate — сертификат, который агент заказывает у центра. Один
// сертификат обслуживает столько эндпоинтов, сколько покрывает: wildcard
// на зону закрывает все её поддомены, а CNAME для проверки владения
// нужен один — на зону, а не на каждое имя.
type Certificate struct {
	Domain   string
	Wildcard bool
}

// Names — имена, которые войдут в сертификат. Состав общий с центром:
// заглушка обязана повторять то, что будет выпущено.
func (c Certificate) Names() []string { return api.CertNames(c.Domain, c.Wildcard) }

// Covers отвечает, годится ли сертификат для домена. Wildcard покрывает
// ровно один уровень: под *.example.com подпадает docs.example.com,
// но не a.docs.example.com.
func (c Certificate) Covers(domain string) bool {
	if c.Domain == domain {
		return true
	}
	if !c.Wildcard {
		return false
	}

	sub, ok := strings.CutSuffix(domain, "."+c.Domain)
	return ok && sub != "" && !strings.Contains(sub, ".")
}

// Certificates возвращает набор сертификатов, которого хватает всем
// эндпоинтам. Домен, попавший под объявленную wildcard-зону, своего
// сертификата не получает — в этом и смысл: один CNAME на зону вместо
// одного на эндпоинт.
func (c *Config) Certificates() []Certificate {
	out := make([]Certificate, 0, len(c.WildcardZones)+len(c.Endpoints))

	for _, z := range c.WildcardZones {
		out = append(out, Certificate{Domain: z, Wildcard: true})
	}

	for _, e := range c.Endpoints {
		if certFor(out, e.Domain) == nil {
			out = append(out, Certificate{Domain: e.Domain})
		}
	}
	return out
}

// certFor выбирает сертификат для домена. Зоны идут в списке первыми,
// поэтому апекс зоны попадает на её же wildcard, а не заводит второй
// сертификат с тем же именем.
func certFor(certs []Certificate, domain string) *Certificate {
	for i := range certs {
		if certs[i].Covers(domain) {
			return &certs[i]
		}
	}
	return nil
}

// certNames сопоставляет домену эндпоинта имя сертификата, под которым
// тот лежит на диске.
func certNames(certs []Certificate, endpoints []Endpoint) map[string]string {
	out := make(map[string]string, len(endpoints))

	for _, e := range endpoints {
		if cert := certFor(certs, e.Domain); cert != nil {
			out[e.Domain] = cert.Domain
		}
	}
	return out
}
