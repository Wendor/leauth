package envsubst

import (
	"strings"
	"testing"
)

func TestExpandSubstitutes(t *testing.T) {
	t.Setenv("LEAUTH_TEST_VALUE", "секрет")

	got, err := Expand("token: ${LEAUTH_TEST_VALUE}")
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if got != "token: секрет" {
		t.Errorf("результат = %q", got)
	}
}

func TestExpandReportsMissing(t *testing.T) {
	_, err := Expand("a: ${НЕТ_ТАКОЙ_1}\nb: ${НЕТ_ТАКОЙ_2}")
	if err == nil {
		t.Fatal("ожидалась ошибка")
	}
	for _, name := range []string{"НЕТ_ТАКОЙ_1", "НЕТ_ТАКОЙ_2"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("в ошибке нет %q: %v", name, err)
		}
	}
}

func TestExpandLeavesPlainText(t *testing.T) {
	got, err := Expand("listen: :8080")
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if got != "listen: :8080" {
		t.Errorf("результат = %q", got)
	}
}

// Знак доллара сам по себе — не ссылка на переменную: он встречается
// в паролях, которые подставляются в конфиг из окружения.
func TestExpandIgnoresBareDollar(t *testing.T) {
	for _, in := range []string{
		"password: p$$w0rd",
		"password: $HOME",
		"upstream: http://app:3000",
	} {
		got, err := Expand(in)
		if err != nil {
			t.Fatalf("Expand(%q): %v", in, err)
		}
		if got != in {
			t.Errorf("Expand(%q) = %q — строку не должно было тронуть", in, got)
		}
	}
}
