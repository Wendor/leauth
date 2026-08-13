package server

import (
	"strings"
	"testing"
	"time"
)

// setRequired задаёт минимум, без которого центр не поднимается.
func setRequired(t *testing.T) {
	t.Helper()

	t.Setenv("LEAUTH_MASTER_KEY", "00112233")
	t.Setenv("ACME_EMAIL", "admin@example.com")
}

func TestLoadConfigFromEnv(t *testing.T) {
	setRequired(t)
	t.Setenv("LEAUTH_LISTEN", "127.0.0.1:9090")
	t.Setenv("RENEW_BEFORE", "720h")
	t.Setenv("CHECK_INTERVAL", "5m")
	t.Setenv("ADMIN_USER", "ops")
	t.Setenv("ADMIN_PASSWORD", "секрет")
	t.Setenv("LEAUTH_ENROLL_TOKEN", "токен-приёма")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("LoadConfigFromEnv: %v", err)
	}

	if cfg.Listen != "127.0.0.1:9090" {
		t.Errorf("listen = %q", cfg.Listen)
	}
	if cfg.MasterKey != "00112233" {
		t.Errorf("master_key = %q", cfg.MasterKey)
	}
	if cfg.RenewBefore != 720*time.Hour {
		t.Errorf("renew_before = %v", cfg.RenewBefore)
	}
	if cfg.CheckInterval != 5*time.Minute {
		t.Errorf("check_interval = %v", cfg.CheckInterval)
	}
	if cfg.Admin.User != "ops" || cfg.Admin.Password != "секрет" {
		t.Errorf("admin = %+v", cfg.Admin)
	}
	if cfg.EnrollToken != "токен-приёма" {
		t.Errorf("enroll_token = %q", cfg.EnrollToken)
	}
}

func TestLoadConfigAppliesDefaults(t *testing.T) {
	setRequired(t)

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("LoadConfigFromEnv: %v", err)
	}

	if cfg.Listen != ":8080" {
		t.Errorf("listen по умолчанию = %q", cfg.Listen)
	}
	if cfg.DB != "/data/leauth.db" {
		t.Errorf("db по умолчанию = %q", cfg.DB)
	}
	if !strings.HasPrefix(cfg.ACME.Directory, "https://acme-v02.api.letsencrypt.org") {
		t.Errorf("directory по умолчанию = %q — ожидался боевой Let's Encrypt", cfg.ACME.Directory)
	}
	if cfg.ACMEDNS.API != "http://acme-dns:8081" {
		t.Errorf("acmedns.api по умолчанию = %q", cfg.ACMEDNS.API)
	}
	// Резолверов по умолчанию несколько: сбой одного не должен
	// останавливать выпуск.
	if len(cfg.Precheck.Resolvers) < 2 || cfg.Precheck.Resolvers[0] != "1.1.1.1:53" {
		t.Errorf("резолверы по умолчанию = %v", cfg.Precheck.Resolvers)
	}
	if cfg.Precheck.Propagation != 5*time.Minute {
		t.Errorf("propagation по умолчанию = %v", cfg.Precheck.Propagation)
	}
	if cfg.RenewBefore != 720*time.Hour {
		t.Errorf("renew_before по умолчанию = %v", cfg.RenewBefore)
	}
	if cfg.CheckInterval != 5*time.Minute {
		t.Errorf("check_interval по умолчанию = %v", cfg.CheckInterval)
	}
	if cfg.Admin.User != "admin" {
		t.Errorf("admin.user по умолчанию = %q", cfg.Admin.User)
	}
}

// Незаданные обязательные переменные должны останавливать запуск, причём
// сообщение обязано называть их: без мастер-ключа приватные ключи в базе
// не расшифровать.
func TestLoadConfigNamesMissingVariables(t *testing.T) {
	t.Setenv("LEAUTH_MASTER_KEY", "")
	t.Setenv("ACME_EMAIL", "")

	_, err := LoadConfigFromEnv()
	if err == nil {
		t.Fatal("ожидалась ошибка: обязательные переменные не заданы")
	}

	for _, name := range []string{"LEAUTH_MASTER_KEY", "ACME_EMAIL"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("в ошибке нет имени переменной %s: %v", name, err)
		}
	}
}

func TestLoadConfigRejectsBadDuration(t *testing.T) {
	setRequired(t)
	t.Setenv("CHECK_INTERVAL", "пять минут")

	if _, err := LoadConfigFromEnv(); err == nil {
		t.Fatal("ожидалась ошибка разбора длительности")
	}
}

func TestResolversParsing(t *testing.T) {
	got := resolvers(" 1.1.1.1 , 8.8.8.8:53 ,, 9.9.9.9:5353 ")

	want := []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:5353"}
	if len(got) != len(want) {
		t.Fatalf("резолверы = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("резолвер %d = %q, ожидался %q", i, got[i], want[i])
		}
	}
}
