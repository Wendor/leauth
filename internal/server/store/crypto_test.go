package store

import (
	"bytes"
	"strings"
	"testing"
)

const testKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func TestCipherRoundTrip(t *testing.T) {
	c, err := NewCipher(testKeyHex)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	plain := []byte("-----BEGIN EC PRIVATE KEY-----")

	blob, err := c.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Contains(blob, plain) {
		t.Error("шифротекст содержит открытый текст")
	}

	got, err := c.Decrypt(blob)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("после расшифровки = %q, ожидалось %q", got, plain)
	}
}

func TestCipherUsesFreshNonce(t *testing.T) {
	c, _ := NewCipher(testKeyHex)

	a, _ := c.Encrypt([]byte("одно и то же"))
	b, _ := c.Encrypt([]byte("одно и то же"))

	if bytes.Equal(a, b) {
		t.Error("два шифрования дали одинаковый результат — nonce не меняется")
	}
}

func TestCipherRejectsTamperedBlob(t *testing.T) {
	c, _ := NewCipher(testKeyHex)

	blob, _ := c.Encrypt([]byte("данные"))
	blob[len(blob)-1] ^= 0xff

	if _, err := c.Decrypt(blob); err == nil {
		t.Fatal("повреждённый шифротекст расшифровался без ошибки")
	}
}

func TestNewCipherRejectsBadKey(t *testing.T) {
	if _, err := NewCipher("слишком-короткий"); err == nil {
		t.Fatal("ожидалась ошибка на некорректном ключе")
	}
	if _, err := NewCipher(strings.Repeat("a", 62)); err == nil {
		t.Fatal("ожидалась ошибка на ключе неверной длины")
	}
}

func TestDecryptRejectsShortBlob(t *testing.T) {
	c, _ := NewCipher(testKeyHex)

	if _, err := c.Decrypt([]byte{1, 2, 3}); err == nil {
		t.Fatal("ожидалась ошибка на слишком коротком блобе")
	}
}
