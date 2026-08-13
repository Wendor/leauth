package api

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateDomain(t *testing.T) {
	ok := map[string]string{
		"  FOO.Example.COM  ": "foo.example.com",
		"foo.example.com.":    "foo.example.com",
		"a-b.c-d.example.com": "a-b.c-d.example.com",
	}
	for in, want := range ok {
		got, err := ValidateDomain(in)
		if err != nil {
			t.Errorf("ValidateDomain(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ValidateDomain(%q) = %q, ожидалось %q", in, got, want)
		}
	}

	bad := []string{
		"",
		"localhost",                              // без точки — не FQDN
		"*.example.com",                          // wildcard задаётся отдельным полем
		"про бел.example.com",                    // пробел
		"foo.example.com; evil",                  // разделитель директив nginx
		"-foo.example.com",                       // метка не может начинаться с дефиса
		"foo-.example.com",                       // и кончаться тоже
		strings.Repeat("a", 64) + ".example.com", // метка длиннее 63
		strings.Repeat("a.", 130) + "example.com", // имя длиннее 253
	}
	for _, in := range bad {
		if got, err := ValidateDomain(in); err == nil {
			t.Errorf("ValidateDomain(%q) = %q без ошибки", in, got)
		}
	}
}

func TestValidateClientName(t *testing.T) {
	got, err := ValidateClientName("  SRV-01  ")
	if err != nil {
		t.Fatalf("ValidateClientName: %v", err)
	}
	if got != "srv-01" {
		t.Errorf("имя = %q, ожидалось srv-01", got)
	}

	for _, in := range []string{"", "srv 01", "../etc", "-srv", strings.Repeat("a", 65)} {
		if _, err := ValidateClientName(in); !errors.Is(err, ErrBadClientName) {
			t.Errorf("имя %q: ошибка = %v, ожидалась ErrBadClientName", in, err)
		}
	}
}

// Состав имён должен совпадать у центра и агента: иначе заглушка на прокси
// закрывала бы не то, что выпускает центр.
func TestCertNames(t *testing.T) {
	if got := CertNames("example.com", false); len(got) != 1 || got[0] != "example.com" {
		t.Errorf("без wildcard = %v", got)
	}

	got := CertNames("example.com", true)
	if len(got) != 2 || got[0] != "example.com" || got[1] != "*.example.com" {
		t.Errorf("с wildcard = %v", got)
	}
}
