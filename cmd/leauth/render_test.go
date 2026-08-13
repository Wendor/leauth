package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderFileSubstitutes(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.tmpl")
	out := filepath.Join(dir, "out.cfg")

	if err := os.WriteFile(in, []byte(`domain = "${LEAUTH_TEST_ZONE}"`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEAUTH_TEST_ZONE", "acme.example.org")

	if err := renderFile(in, out); err != nil {
		t.Fatalf("renderFile: %v", err)
	}

	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `domain = "acme.example.org"` {
		t.Errorf("результат = %q", got)
	}
}

// Незаданная переменная не должна давать пустое значение: конфиг с пустой
// зоной acme-dns запустится, но не будет отвечать ни на один запрос.
func TestRenderFileFailsOnMissingVar(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.tmpl")
	out := filepath.Join(dir, "out.cfg")

	if err := os.WriteFile(in, []byte(`domain = "${LEAUTH_TEST_НЕТ_ТАКОЙ}"`), 0o644); err != nil {
		t.Fatal(err)
	}

	err := renderFile(in, out)
	if err == nil {
		t.Fatal("ожидалась ошибка")
	}
	if !strings.Contains(err.Error(), "LEAUTH_TEST_НЕТ_ТАКОЙ") {
		t.Errorf("в ошибке нет имени переменной: %v", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Error("при ошибке файл не должен создаваться")
	}
}

// Шаблон acme-dns подставляется в compose, опечатка в имени переменной
// обнаружилась бы только на боевом развёртывании.
func TestRenderACMEDNSTemplate(t *testing.T) {
	t.Setenv("ACMEDNS_ZONE", "acme.example.org")
	t.Setenv("ACMEDNS_NS_HOST", "ns-acme.example.org")
	// Точки внутри имени ящика экранируются, поэтому значение попадает
	// в литеральную строку TOML — в обычной конфиг не распарсится.
	t.Setenv("ACMEDNS_ADMIN", `a\.ivanov.example.org`)
	t.Setenv("ACMEDNS_PUBLIC_IP", "198.51.100.7")
	t.Setenv("ACMEDNS_LISTEN", "0.0.0.0:53")

	out := filepath.Join(t.TempDir(), "config.cfg")
	if err := renderFile("../../deploy/central/acme-dns.cfg.tmpl", out); err != nil {
		t.Fatalf("renderFile: %v", err)
	}

	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)

	if strings.Contains(got, "${") {
		t.Errorf("в результате осталась неподставленная переменная:\n%s", got)
	}

	want := []string{
		`domain = "acme.example.org"`,
		`nsname = "ns-acme.example.org"`,
		`nsadmin = 'a\.ivanov.example.org'`,
		`"acme.example.org. A 198.51.100.7"`,
		`"acme.example.org. NS ns-acme.example.org."`,
		`"ns-acme.example.org. A 198.51.100.7"`,
		`listen = "0.0.0.0:53"`,
	}
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("нет строки %s в:\n%s", w, got)
		}
	}
}
