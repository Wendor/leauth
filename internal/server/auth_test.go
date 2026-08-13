package server

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"leauth/internal/api"
	"leauth/internal/server/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()

	c, err := store.NewCipher("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	st, err := store.Open(filepath.Join(t.TempDir(), "auth.db"), c)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	return st
}

func TestHashTokenIsStable(t *testing.T) {
	a := HashToken("секретный-токен")
	b := HashToken("секретный-токен")

	if a != b {
		t.Error("хеш одного токена должен совпадать")
	}
	if a == HashToken("другой-токен") {
		t.Error("разные токены дали одинаковый хеш")
	}
	if len(a) != 64 {
		t.Errorf("длина хеша = %d, ожидалось 64 hex-символа", len(a))
	}
}

func TestEnrollIssuesUsableToken(t *testing.T) {
	ctx := context.Background()
	a := NewAuthenticator(newTestStore(t), "токен-приёма")

	_, token, err := a.Enroll(ctx, "srv-01")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if len(token) != 64 {
		t.Errorf("длина выданного токена = %d, ожидалось 64 hex-символа", len(token))
	}
	if token == "токен-приёма" {
		t.Fatal("выдан общий токен приёма вместо персонального")
	}

	name, ok := a.ClientFor(ctx, "Bearer "+token)
	if !ok {
		t.Fatal("выданный токен не принимается")
	}
	if name != "srv-01" {
		t.Errorf("клиент = %q, ожидался srv-01", name)
	}
}

// Токены персональные: у второго прокси свой, и он не совпадает с первым.
func TestEnrollGivesEachProxyItsOwnToken(t *testing.T) {
	ctx := context.Background()
	a := NewAuthenticator(newTestStore(t), "токен-приёма")

	_, first, err := a.Enroll(ctx, "srv-01")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	_, second, err := a.Enroll(ctx, "srv-02")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	if first == second {
		t.Fatal("двум прокси выдан один токен")
	}

	name, _ := a.ClientFor(ctx, "Bearer "+first)
	if name != "srv-01" {
		t.Errorf("первый токен опознан как %q", name)
	}
}

// Прокси, потерявший том, возвращается под тем же именем: старый токен
// перестаёт работать, новый работает.
func TestReEnrollReplacesToken(t *testing.T) {
	ctx := context.Background()
	a := NewAuthenticator(newTestStore(t), "токен-приёма")

	_, old, err := a.Enroll(ctx, "srv-01")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	_, fresh, err := a.Enroll(ctx, "srv-01")
	if err != nil {
		t.Fatalf("повторный Enroll: %v", err)
	}

	if _, ok := a.ClientFor(ctx, "Bearer "+old); ok {
		t.Error("старый токен должен перестать работать")
	}
	if name, ok := a.ClientFor(ctx, "Bearer "+fresh); !ok || name != "srv-01" {
		t.Errorf("новый токен не работает: %q, %v", name, ok)
	}
}

// Право на приём проверяется отдельно от тела запроса: ручка отказывает
// до того, как разберёт присланный анонимом JSON.
func TestCheckEnrollRejects(t *testing.T) {
	a := NewAuthenticator(newTestStore(t), "токен-приёма")

	cases := []struct {
		name   string
		header string
		want   error
	}{
		{"чужой токен", "Bearer другой", ErrEnrollDenied},
		{"без заголовка", "", ErrEnrollDenied},
		{"не bearer", "Basic токен-приёма", ErrEnrollDenied},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if err := a.CheckEnroll(tt.header); !errors.Is(err, tt.want) {
				t.Errorf("ошибка = %v, ожидалась %v", err, tt.want)
			}
		})
	}

	if err := a.CheckEnroll("Bearer токен-приёма"); err != nil {
		t.Errorf("верный токен приёма отвергнут: %v", err)
	}
}

func TestEnrollRejectsBadNames(t *testing.T) {
	ctx := context.Background()
	a := NewAuthenticator(newTestStore(t), "токен-приёма")

	for _, name := range []string{"", "srv 01", "../etc", "-srv", strings.Repeat("a", 65)} {
		if _, _, err := a.Enroll(ctx, name); !errors.Is(err, api.ErrBadClientName) {
			t.Errorf("имя %q: ошибка = %v, ожидалась ErrBadClientName", name, err)
		}
	}
}

// Имя приводится к канону, чтобы SRV-01 и srv-01 не заводили два прокси.
func TestEnrollNormalizesName(t *testing.T) {
	name, _, err := NewAuthenticator(newTestStore(t), "токен-приёма").
		Enroll(context.Background(), "  SRV-01  ")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if name != "srv-01" {
		t.Errorf("имя = %q, ожидалось srv-01", name)
	}
}

// Без токена приёма центр не принимает никого — так закрывается приём,
// когда парк прокси собран.
func TestEnrollClosedWithoutToken(t *testing.T) {
	a := NewAuthenticator(newTestStore(t), "")

	if err := a.CheckEnroll("Bearer что-угодно"); !errors.Is(err, ErrEnrollClosed) {
		t.Errorf("ошибка = %v, ожидалась ErrEnrollClosed", err)
	}
}

// Отзыв прокси лишает его токен силы: это единственный способ отключить
// скомпрометированный прокси, пока центр продолжает работать.
func TestRevokeDisablesToken(t *testing.T) {
	ctx := context.Background()
	a := NewAuthenticator(newTestStore(t), "токен-приёма")

	_, token, err := a.Enroll(ctx, "srv-01")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if _, ok := a.ClientFor(ctx, "Bearer "+token); !ok {
		t.Fatal("выданный токен не принимается")
	}

	if err := a.Revoke(ctx, "SRV-01"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, ok := a.ClientFor(ctx, "Bearer "+token); ok {
		t.Error("токен отозванного прокси всё ещё принимается")
	}
}

func TestClientForRejects(t *testing.T) {
	ctx := context.Background()
	a := NewAuthenticator(newTestStore(t), "токен-приёма")

	_, token, err := a.Enroll(ctx, "srv-01")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	for _, header := range []string{
		"",
		token,
		"Bearer",
		"Bearer ",
		"Bearer неизвестный",
		"Basic " + token,
		// Токен приёма не даёт доступа к API доменов.
		"Bearer токен-приёма",
	} {
		if _, ok := a.ClientFor(ctx, header); ok {
			t.Errorf("заголовок %q не должен приниматься", header)
		}
	}
}
