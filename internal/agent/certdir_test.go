package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriteAndReadBack(t *testing.T) {
	d := NewCertDir(t.TempDir())

	certPEM, keyPEM, err := GenerateSelfSigned("foo.example.com")
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	if err := d.Write("foo.example.com", certPEM, keyPEM); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if !d.Usable("foo.example.com") {
		t.Error("файлы не появились")
	}

	fullchain, key := d.Paths("foo.example.com")
	if !strings.HasSuffix(fullchain, "fullchain.pem") || !strings.HasSuffix(key, "privkey.pem") {
		t.Errorf("неожиданные пути: %s, %s", fullchain, key)
	}

	info, err := os.Stat(key)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("права на ключ = %o, ожидалось 600", perm)
	}

	if serial := d.Serial("foo.example.com"); serial == "" {
		t.Error("серийный номер не прочитан")
	}
}

func TestWriteRejectsMismatchedPair(t *testing.T) {
	d := NewCertDir(t.TempDir())

	certPEM, _, _ := GenerateSelfSigned("foo.example.com")
	_, otherKey, _ := GenerateSelfSigned("foo.example.com")

	if err := d.Write("foo.example.com", certPEM, otherKey); err == nil {
		t.Fatal("несовпадающая пара должна отклоняться")
	}
	if d.Usable("foo.example.com") {
		t.Error("при отказе файлы записываться не должны")
	}
}

func TestWriteRejectsGarbage(t *testing.T) {
	d := NewCertDir(t.TempDir())

	if err := d.Write("foo.example.com", []byte("не PEM"), []byte("тоже не PEM")); err == nil {
		t.Fatal("мусор должен отклоняться")
	}
}

func TestWriteReplacesExisting(t *testing.T) {
	root := t.TempDir()
	d := NewCertDir(root)

	first, firstKey, _ := GenerateSelfSigned("foo.example.com")
	if err := d.Write("foo.example.com", first, firstKey); err != nil {
		t.Fatalf("первая запись: %v", err)
	}

	firstSerial := d.Serial("foo.example.com")

	second, secondKey, _ := GenerateSelfSigned("foo.example.com")
	if err := d.Write("foo.example.com", second, secondKey); err != nil {
		t.Fatalf("вторая запись: %v", err)
	}

	secondSerial := d.Serial("foo.example.com")
	if firstSerial == secondSerial {
		t.Error("сертификат не заменился")
	}

	entries, err := os.ReadDir(filepath.Join(root, "foo.example.com"))
	if err != nil {
		t.Fatalf("чтение каталога: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("файлов в каталоге: %d, ожидалось 2 — остались временные", len(entries))
	}
}

func TestSerialOnMissingIsEmpty(t *testing.T) {
	d := NewCertDir(t.TempDir())

	if serial := d.Serial("нет.example.com"); serial != "" {
		t.Errorf("серийный номер = %q, ожидалась пустая строка", serial)
	}
}

// Заглушку от выпущенного сертификата отличает совпадение издателя
// с субъектом: агент по этому признаку решает, ждать ли ему настоящий.
func TestSelfSigned(t *testing.T) {
	dir := NewCertDir(t.TempDir())

	// Файла нет — настоящего сертификата тем более.
	got := dir.SelfSigned("нет.example.com")
	if !got {
		t.Error("отсутствующий сертификат должен считаться заглушкой")
	}

	certPEM, keyPEM, err := GenerateSelfSigned("a.example.com")
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	if err := dir.Write("a.example.com", certPEM, keyPEM); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got = dir.SelfSigned("a.example.com")
	if !got {
		t.Error("заглушка не опознана")
	}

	caPEM, leafPEM, leafKeyPEM := issueSignedCert(t, "b.example.com")
	if err := dir.Write("b.example.com", append(leafPEM, caPEM...), leafKeyPEM); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got = dir.SelfSigned("b.example.com")
	if got {
		t.Error("подписанный чужим CA сертификат принят за заглушку")
	}
}

// issueSignedCert выпускает лист, подписанный отдельным CA, — так же
// устроена цепочка от Let's Encrypt.
func issueSignedCert(t *testing.T, domain string) (caPEM, leafPEM, leafKeyPEM []byte) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "тестовый CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
