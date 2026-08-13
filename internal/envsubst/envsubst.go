// Package envsubst подставляет переменные окружения в конфигурационные файлы.
package envsubst

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// refRe — только полная форма ${VAR}. Сокращённую $VAR тут поддерживать
// нельзя: в конфиг попадают пароли, а знак доллара в пароле превратил бы
// его в ссылку на несуществующую переменную и остановил запуск.
//
// Имя берётся любое непустое: незаданная переменная должна давать ошибку,
// а не тихо оставаться в конфиге текстом ${...}.
var refRe = regexp.MustCompile(`\$\{([^{}\s]+)\}`)

// Expand заменяет ${VAR} значениями переменных окружения.
// Незаданная переменная — ошибка, а не пустая строка: пустой токен
// или мастер-ключ молча сломали бы безопасность.
func Expand(s string) (string, error) {
	var missing []string
	seen := map[string]bool{}

	out := refRe.ReplaceAllStringFunc(s, func(ref string) string {
		name := refRe.FindStringSubmatch(ref)[1]

		v, ok := os.LookupEnv(name)
		if ok {
			return v
		}
		if !seen[name] {
			seen[name] = true
			missing = append(missing, name)
		}
		return ""
	})

	if len(missing) > 0 {
		return "", fmt.Errorf("не заданы переменные окружения: %s", strings.Join(missing, ", "))
	}
	return out, nil
}
