package server

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunFailsOnBadMasterKey(t *testing.T) {
	cfg := &Config{
		Listen:    "127.0.0.1:0",
		DB:        filepath.Join(t.TempDir(), "run.db"),
		MasterKey: "не-hex",
		ACME:      ACMEConfig{Directory: "https://example.com/dir", Email: "a@b.c"},
		ACMEDNS:   ACMEDNSConfig{API: "http://127.0.0.1:1"},
		Precheck:  PrecheckConfig{Resolvers: []string{"1.1.1.1:53"}},

		RenewBefore:   30 * 24 * time.Hour,
		CheckInterval: 5 * time.Minute,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := Run(ctx, cfg)
	if err == nil {
		t.Fatal("ожидалась ошибка мастер-ключа")
	}
	if !strings.Contains(err.Error(), "мастер-ключ") {
		t.Errorf("ошибка = %v", err)
	}
}
