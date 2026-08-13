package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"leauth/internal/api"
	"leauth/internal/server/store"
)

// Ошибки приёма прокси. Разделены, чтобы ручка отвечала разными кодами:
// закрытый приём и неверный токен — разные состояния для того, кто
// разбирается с развёртыванием.
var (
	ErrEnrollClosed = errors.New("приём новых прокси закрыт: не задан enroll_token")
	ErrEnrollDenied = errors.New("неверный токен приёма")
)

// HashToken возвращает hex от SHA-256. Токены прокси длинные и случайные,
// поэтому медленная функция вроде bcrypt здесь не нужна, а вредна:
// проверка идёт на каждом запросе агента.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Authenticator сопоставляет предъявленный токен имени прокси и выдаёт
// токены новым. Токены живут в базе, а не в конфиге: добавление прокси
// не должно требовать правки файла и перезапуска центра.
type Authenticator struct {
	store       *store.Store
	enrollToken string
}

func NewAuthenticator(s *store.Store, enrollToken string) *Authenticator {
	return &Authenticator{store: s, enrollToken: enrollToken}
}

// ClientFor разбирает заголовок Authorization и возвращает имя прокси.
func (a *Authenticator) ClientFor(ctx context.Context, header string) (string, bool) {
	token, ok := bearer(header)
	if !ok {
		return "", false
	}

	name, err := a.store.ClientByTokenHash(ctx, HashToken(token))
	if errors.Is(err, store.ErrNotFound) {
		return "", false
	}
	if err != nil {
		slog.Error("проверка токена", "ошибка", err)
		return "", false
	}
	return name, true
}

// CheckEnroll проверяет только право на приём. Отделено от Enroll, чтобы
// ручка могла отказать до разбора тела запроса: разбирать присланный
// аноним JSON центр не обязан.
func (a *Authenticator) CheckEnroll(header string) error {
	if a.enrollToken == "" {
		return ErrEnrollClosed
	}

	token, ok := bearer(header)
	if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(a.enrollToken)) != 1 {
		return ErrEnrollDenied
	}
	return nil
}

// Enroll заводит прокси и выдаёт ему персональный токен, возвращая
// приведённое к канону имя. Право на приём проверяет вызывающий: ручка
// отказывает до чтения тела запроса, поэтому CheckEnroll к этому моменту
// уже пройден.
//
// Повторный приём под тем же именем заменяет токен: прокси, потерявший
// свой том, должен возвращаться в строй без действий на центре.
func (a *Authenticator) Enroll(ctx context.Context, name string) (string, string, error) {
	name, err := api.ValidateClientName(name)
	if err != nil {
		return "", "", err
	}

	issued, err := newToken()
	if err != nil {
		return "", "", err
	}

	if err := a.store.SaveClient(ctx, name, HashToken(issued)); err != nil {
		return "", "", err
	}
	return name, issued, nil
}

// Revoke отключает прокси: удаляет его токен и снимает с него домены.
// Единственный способ отозвать доступ у скомпрометированного прокси —
// персональный токен иначе действует бессрочно.
func (a *Authenticator) Revoke(ctx context.Context, name string) error {
	name, err := api.ValidateClientName(name)
	if err != nil {
		return err
	}
	return a.store.DeleteClient(ctx, name)
}

// newToken — 32 случайных байта в hex. Токен предъявляется на каждом
// запросе агента и хранится в центре только хешем.
func newToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("генерация токена: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func bearer(header string) (string, bool) {
	token, ok := strings.CutPrefix(header, "Bearer ")
	return token, ok && token != ""
}
