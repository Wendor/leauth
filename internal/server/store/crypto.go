package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

// Cipher шифрует секреты, которые лежат в БД: приватные ключи
// сертификатов и пароли acme-dns.
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher принимает мастер-ключ в виде 64 шестнадцатеричных символов
// (32 байта). Ключ берётся из переменной окружения LEAUTH_MASTER_KEY.
func NewCipher(hexKey string) (*Cipher, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("мастер-ключ не является hex-строкой: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("мастер-ключ должен быть 32 байта (64 hex-символа), получено %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// Encrypt возвращает nonce, за которым следует шифротекст.
func (c *Cipher) Encrypt(plain []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("генерация nonce: %w", err)
	}
	return c.aead.Seal(nonce, nonce, plain, nil), nil
}

func (c *Cipher) Decrypt(blob []byte) ([]byte, error) {
	ns := c.aead.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("шифротекст короче nonce")
	}

	plain, err := c.aead.Open(nil, blob[:ns], blob[ns:], nil)
	if err != nil {
		return nil, fmt.Errorf("расшифровка не удалась: %w", err)
	}
	return plain, nil
}
