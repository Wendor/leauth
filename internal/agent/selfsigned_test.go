package agent

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestGenerateSelfSignedProducesUsablePair(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSigned("foo.example.com")
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("пара не принимается crypto/tls: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("сертификат не PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}

	if err := cert.VerifyHostname("foo.example.com"); err != nil {
		t.Errorf("SAN не содержит домен: %v", err)
	}
	if cert.NotAfter.Before(time.Now().Add(24 * time.Hour)) {
		t.Error("заглушка истекает слишком быстро")
	}
}
