package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/urfave/cli/v3"
)

func runVerifyWith(args ...string) error {
	app := &cli.Command{
		Name:     "certificate-utils",
		Commands: []*cli.Command{verifyCmd},
	}
	return app.Run(context.Background(), append([]string{"certificate-utils", "verify"}, args...))
}

func TestKeyPairMatches(t *testing.T) {
	ca := newTestCA(t)

	serverCert := ca.newServerCert(t, []string{"example.com"})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Certificate[0]})
	certBundle, _, err := parseCertInput(certPEM, "")
	if err != nil {
		t.Fatalf("parseCertInput cert: %v", err)
	}

	match, err := keyPairMatches(certBundle.certs[0].PublicKey, serverCert.PrivateKey)
	if err != nil {
		t.Fatalf("keyPairMatches: %v", err)
	}
	if !match {
		t.Fatalf("expected matching cert/key pair to match")
	}

	other := ca.newServerCert(t, []string{"other.com"})
	otherPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.Certificate[0]})
	otherBundle, _, err := parseCertInput(otherPEM, "")
	if err != nil {
		t.Fatalf("parseCertInput other: %v", err)
	}
	mismatch, err := keyPairMatches(otherBundle.certs[0].PublicKey, serverCert.PrivateKey)
	if err != nil {
		t.Fatalf("keyPairMatches: %v", err)
	}
	if mismatch {
		t.Fatalf("expected different cert/key pair not to match")
	}
}

func TestRunVerify(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.newServerCert(t, []string{"example.com"})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Certificate[0]})

	ecKey, ok := serverCert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected ecdsa private key")
	}
	keyDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshal EC key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certPath := writeTempFile(t, "server-*.crt", certPEM)
	keyPath := writeTempFile(t, "server-*.key", keyPEM)

	if err := runVerifyWith(certPath, keyPath); err != nil {
		t.Fatalf("verify matching pair: %v", err)
	}

	other := ca.newServerCert(t, []string{"other.com"})
	otherPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.Certificate[0]})
	otherCertPath := writeTempFile(t, "other-*.crt", otherPEM)

	if err := runVerifyWith(otherCertPath, keyPath); err == nil {
		t.Fatalf("expected error for mismatched cert/key pair")
	}
}
