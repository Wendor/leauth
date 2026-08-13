package api

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// domainRe допускает только имена в нижнем регистре без wildcard:
// wildcard задаётся отдельным полем запроса. Проверка общая для центра
// и агента: центр защищает ею свою базу, агент — конфиг nginx, куда имя
// попадает в server_name.
var domainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// ValidateDomain приводит имя к нижнему регистру и проверяет его форму.
func ValidateDomain(name string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimSuffix(name, ".")

	if name == "" {
		return "", errors.New("пустое имя домена")
	}
	if len(name) > 253 {
		return "", errors.New("имя домена длиннее 253 символов")
	}
	for label := range strings.SplitSeq(name, ".") {
		if len(label) > 63 {
			return "", fmt.Errorf("метка %q длиннее 63 символов", label)
		}
	}
	if !domainRe.MatchString(name) {
		return "", fmt.Errorf("некорректное имя домена: %q", name)
	}
	return name, nil
}

// clientNameRe — имя прокси попадает в логи и на страницу статуса,
// поэтому набор символов узкий.
var clientNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ErrBadClientName один на обе стороны: центр отвечает им на приём,
// агент — отказом стартовать с негодным именем в конфиге.
var ErrBadClientName = errors.New("имя прокси: латиница, цифры, дефис, точка и подчёркивание, до 64 символов")

// ValidateClientName приводит имя прокси к нижнему регистру и проверяет
// его форму. Проверка одна и та же на прокси и в центре: иначе агент
// стартовал бы с именем, которое центр не примет.
func ValidateClientName(name string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if !clientNameRe.MatchString(name) {
		return "", ErrBadClientName
	}
	return name, nil
}

// CertNames — имена, которые входят в сертификат для домена. Общая
// функция: агент по ней создаёт заглушку, центр — заказывает выпуск,
// и состав имён обязан совпадать.
func CertNames(domain string, wildcard bool) []string {
	if wildcard {
		return []string{domain, "*." + domain}
	}
	return []string{domain}
}
