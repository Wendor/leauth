package agent

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// CertDir хранит сертификаты в <root>/<домен>/{fullchain,privkey}.pem.
type CertDir struct {
	root string
}

func NewCertDir(root string) *CertDir {
	return &CertDir{root: root}
}

func (d *CertDir) Paths(domain string) (string, string) {
	dir := filepath.Join(d.root, domain)
	return filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
}

// Usable отвечает, лежит ли на месте домена пара, с которой nginx
// поднимется. Простого наличия файлов мало: обрезанный или рассогласованный
// после сбоя питания сертификат не даст nginx стартовать вообще, и агент
// уйдёт в бесконечный перезапуск. Негодная пара считается отсутствующей —
// поверх неё будет записана свежая заглушка.
func (d *CertDir) Usable(domain string) bool {
	fullchain, key := d.Paths(domain)

	certPEM, err := os.ReadFile(fullchain)
	if err != nil {
		return false
	}
	keyPEM, err := os.ReadFile(key)
	if err != nil {
		return false
	}

	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		slog.Warn("на диске негодная пара сертификат/ключ, будет заменена",
			"домен", domain, "ошибка", err)
		return false
	}
	return true
}

// Write проверяет, что цепочка разбирается и ключ ей соответствует,
// и только потом заменяет файлы. Битый материал не должен доходить
// до nginx: reload с ним не пройдёт.
func (d *CertDir) Write(domain string, fullchainPEM, keyPEM []byte) error {
	if _, err := tls.X509KeyPair(fullchainPEM, keyPEM); err != nil {
		return fmt.Errorf("сертификат и ключ для %s не подходят друг к другу: %w", domain, err)
	}

	dir := filepath.Join(d.root, domain)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("создание каталога %s: %w", dir, err)
	}

	fullchain, key := d.Paths(domain)

	if err := writeAtomic(key, keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeAtomic(fullchain, fullchainPEM, 0o644); err != nil {
		return err
	}
	return nil
}

// writeAtomic пишет во временный файл рядом с целевым и переименовывает:
// частично записанный файл никогда не попадёт под nginx.
func writeAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("временный файл в %s: %w", dir, err)
	}
	tmpName := tmp.Name()

	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("запись %s: %w", tmpName, err)
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("права на %s: %w", tmpName, err)
	}
	// Без сброса на диск rename переживёт сбой питания, а содержимое —
	// нет: на месте сертификата останется нуль байт, и nginx не поднимется.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("сброс %s на диск: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("закрытие %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("переименование в %s: %w", path, err)
	}
	return nil
}

// leaf разбирает листовой сертификат домена. Нечитаемый файл — не ошибка,
// а отсутствие сертификата: битую или недописанную цепочку нужно заменить
// свежей, а не останавливать из-за неё агента. Возвращается nil.
func (d *CertDir) leaf(domain string) *x509.Certificate {
	fullchain, _ := d.Paths(domain)

	raw, err := os.ReadFile(fullchain)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Warn("не удалось прочитать сертификат", "файл", fullchain, "ошибка", err)
		}
		return nil
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		slog.Warn("сертификат не является PEM", "файл", fullchain)
		return nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		slog.Warn("не удалось разобрать сертификат", "файл", fullchain, "ошибка", err)
		return nil
	}
	return cert
}

// SelfSigned отвечает, лежит ли на месте домена заглушка, а не выпущенный
// центром сертификат. Отсутствующий или нечитаемый файл тоже считается
// заглушкой: настоящего сертификата там тем более нет, и спросить центр
// лишний раз дешевле, чем застрять.
//
// Признак — совпадение издателя с субъектом: у сертификата Let's Encrypt
// они всегда разные.
func (d *CertDir) SelfSigned(domain string) bool {
	cert := d.leaf(domain)
	if cert == nil {
		return true
	}
	return bytes.Equal(cert.RawIssuer, cert.RawSubject)
}

// Serial возвращает серийный номер лежащего на диске сертификата
// в том же виде, что и центр. Пустая строка означает, что годного
// сертификата нет и центр должен прислать его целиком.
func (d *CertDir) Serial(domain string) string {
	cert := d.leaf(domain)
	if cert == nil {
		return ""
	}
	return cert.SerialNumber.Text(16)
}
