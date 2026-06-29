package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/urfave/cli/v3"
)

func runConvertWith(args ...string) error {
	app := &cli.Command{
		Name:     "certificate-utils",
		Commands: []*cli.Command{convertCmd},
	}
	return app.Run(context.Background(), append([]string{"certificate-utils", "convert"}, args...))
}

func TestParseCertInput_PEM(t *testing.T) {
	ca := newTestCA(t)
	bundle, fmt, err := parseCertInput(ca.pemData, "")
	if err != nil {
		t.Fatalf("parseCertInput: %v", err)
	}
	if fmt != "PEM" {
		t.Errorf("format = %q, want PEM", fmt)
	}
	if len(bundle.certs) != 1 {
		t.Errorf("got %d cert(s), want 1", len(bundle.certs))
	}
}

func TestParseCertInput_DER(t *testing.T) {
	ca := newTestCA(t)
	bundle, inputFmt, err := parseCertInput(ca.cert.Raw, "")
	if err != nil {
		t.Fatalf("parseCertInput: %v", err)
	}
	if inputFmt != "DER/CRT" {
		t.Errorf("format = %q, want DER/CRT", inputFmt)
	}
	if len(bundle.certs) != 1 {
		t.Errorf("got %d cert(s), want 1", len(bundle.certs))
	}
}

func TestParseCertInput_Invalid(t *testing.T) {
	if _, _, err := parseCertInput([]byte("not a certificate at all"), ""); err == nil {
		t.Error("expected error for unrecognized input")
	}
}

func TestParsePEMBundle_MultiCert(t *testing.T) {
	ca := newTestCA(t)
	tlsCert := ca.newServerCert(t, []string{"localhost"})
	serverPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsCert.Certificate[0]})

	bundle, err := parsePEMBundle(append(ca.pemData, serverPEM...))
	if err != nil {
		t.Fatalf("parsePEMBundle: %v", err)
	}
	if len(bundle.certs) != 2 {
		t.Errorf("got %d cert(s), want 2", len(bundle.certs))
	}
}

func TestParsePEMBundle_NoCerts(t *testing.T) {
	input := []byte("-----BEGIN OTHER-----\nYWJj\n-----END OTHER-----\n")
	if _, err := parsePEMBundle(input); err == nil {
		t.Error("expected error when PEM contains no CERTIFICATE blocks")
	}
}

func TestParsePEMBundle_InvalidCertBlock(t *testing.T) {
	input := []byte("-----BEGIN CERTIFICATE-----\nbm90dmFsaWQ=\n-----END CERTIFICATE-----\n")
	if _, err := parsePEMBundle(input); err == nil {
		t.Error("expected error for malformed certificate DER")
	}
}

func TestConvertWriteText(t *testing.T) {
	ca := newTestCA(t)
	bundle := &certBundle{certs: []*x509.Certificate{ca.cert}}

	var buf bytes.Buffer
	if err := convertWriteText(&buf, bundle); err != nil {
		t.Fatalf("convertWriteText: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"Subject:", "Issuer:", "Not Before:", "Not After:", "Test CA"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestConvertWriteText_MultiCert(t *testing.T) {
	ca := newTestCA(t)
	tlsCert := ca.newServerCert(t, []string{"localhost"})
	serverX509, _ := x509.ParseCertificate(tlsCert.Certificate[0])

	bundle := &certBundle{certs: []*x509.Certificate{ca.cert, serverX509}}

	var buf bytes.Buffer
	if err := convertWriteText(&buf, bundle); err != nil {
		t.Fatalf("convertWriteText: %v", err)
	}

	if count := strings.Count(buf.String(), "Subject:"); count != 2 {
		t.Errorf("expected 2 Subject: lines, got %d", count)
	}
}

func TestConvertWriteText_WithKey(t *testing.T) {
	ca := newTestCA(t)
	bundle := &certBundle{certs: []*x509.Certificate{ca.cert}, privateKey: ca.key}

	var buf bytes.Buffer
	if err := convertWriteText(&buf, bundle); err != nil {
		t.Fatalf("convertWriteText: %v", err)
	}

	if !strings.Contains(buf.String(), "Private key present") {
		t.Error("expected 'Private key present' in output")
	}
}

func TestConvertWritePEM_RoundTrip(t *testing.T) {
	ca := newTestCA(t)
	bundle := &certBundle{certs: []*x509.Certificate{ca.cert}}

	var buf bytes.Buffer
	if err := convertWritePEM(&buf, bundle); err != nil {
		t.Fatalf("convertWritePEM: %v", err)
	}

	block, _ := pem.Decode(buf.Bytes())
	if block == nil {
		t.Fatal("output is not valid PEM")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse round-tripped cert: %v", err)
	}
	if parsed.Subject.CommonName != "Test CA" {
		t.Errorf("CN = %q, want 'Test CA'", parsed.Subject.CommonName)
	}
}

func TestConvertWritePEM_WithKey(t *testing.T) {
	ca := newTestCA(t)
	bundle := &certBundle{certs: []*x509.Certificate{ca.cert}, privateKey: ca.key}

	var buf bytes.Buffer
	if err := convertWritePEM(&buf, bundle); err != nil {
		t.Fatalf("convertWritePEM: %v", err)
	}

	if !strings.Contains(buf.String(), "-----BEGIN PRIVATE KEY-----") {
		t.Error("expected PRIVATE KEY block in PEM output")
	}
}

func TestConvertWriteDER_RoundTrip(t *testing.T) {
	ca := newTestCA(t)
	bundle := &certBundle{certs: []*x509.Certificate{ca.cert}}

	var buf bytes.Buffer
	if err := convertWriteDER(&buf, bundle); err != nil {
		t.Fatalf("convertWriteDER: %v", err)
	}

	parsed, err := x509.ParseCertificate(buf.Bytes())
	if err != nil {
		t.Fatalf("parse round-tripped DER: %v", err)
	}
	if parsed.Subject.CommonName != "Test CA" {
		t.Errorf("CN = %q, want 'Test CA'", parsed.Subject.CommonName)
	}
}

func TestConvertWriteDER_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := convertWriteDER(&buf, &certBundle{}); err == nil {
		t.Error("expected error for empty bundle")
	}
}

func TestConvertWriteDER_MultipleWritesFirst(t *testing.T) {
	ca := newTestCA(t)
	tlsCert := ca.newServerCert(t, []string{"localhost"})
	serverX509, _ := x509.ParseCertificate(tlsCert.Certificate[0])

	bundle := &certBundle{certs: []*x509.Certificate{ca.cert, serverX509}}

	var buf bytes.Buffer
	if err := convertWriteDER(&buf, bundle); err != nil {
		t.Fatalf("convertWriteDER: %v", err)
	}

	if !bytes.Equal(buf.Bytes(), ca.cert.Raw) {
		t.Error("expected first certificate's DER when bundle has multiple certs")
	}
}

func TestEW_PropagatesFirstError(t *testing.T) {
	e := &ew{w: &failWriter{}}
	e.printf("first write")
	firstErr := e.err
	if firstErr == nil {
		t.Fatal("expected error after write to failing writer")
	}
	e.println("second write should be skipped")
	if e.err != firstErr {
		t.Error("expected error to remain unchanged after first failure")
	}
}

type failWriter struct{}

func (f *failWriter) Write(_ []byte) (int, error) {
	return 0, fmt.Errorf("write failed")
}

// Integration tests — convert command via CLI.

func TestRunConvert_PEMToText(t *testing.T) {
	ca := newTestCA(t)
	f := writeTempFile(t, "cert-*.pem", ca.pemData)

	if err := runConvertWith("--format", "text", f); err != nil {
		t.Errorf("expected success: %v", err)
	}
}

func TestRunConvert_DERToText(t *testing.T) {
	ca := newTestCA(t)
	f := writeTempFile(t, "cert-*.crt", ca.cert.Raw)

	if err := runConvertWith("--format", "text", f); err != nil {
		t.Errorf("expected success for DER input: %v", err)
	}
}

func TestRunConvert_PEMToPEM(t *testing.T) {
	ca := newTestCA(t)
	inFile := writeTempFile(t, "in-*.pem", ca.pemData)
	outFile := inFile + ".out"
	t.Cleanup(func() { _ = os.Remove(outFile) })

	if err := runConvertWith("--format", "pem", "--out", outFile, inFile); err != nil {
		t.Fatalf("expected success: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if !strings.Contains(string(data), "-----BEGIN CERTIFICATE-----") {
		t.Error("expected PEM block in output file")
	}
}

func TestRunConvert_PEMToDER(t *testing.T) {
	ca := newTestCA(t)
	inFile := writeTempFile(t, "in-*.pem", ca.pemData)
	outFile := inFile + ".crt"
	t.Cleanup(func() { _ = os.Remove(outFile) })

	if err := runConvertWith("--format", "crt", "--out", outFile, inFile); err != nil {
		t.Fatalf("expected success: %v", err)
	}

	data, _ := os.ReadFile(outFile)
	if _, err := x509.ParseCertificate(data); err != nil {
		t.Errorf("output is not valid DER: %v", err)
	}
}

func TestRunConvert_InvalidFormat(t *testing.T) {
	ca := newTestCA(t)
	f := writeTempFile(t, "cert-*.pem", ca.pemData)

	if err := runConvertWith("--format", "jsonl", f); err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestRunConvert_MissingFile(t *testing.T) {
	if err := runConvertWith("/nonexistent/cert.pem"); err == nil {
		t.Error("expected error for missing input file")
	}
}

func TestRunConvert_EmptyInput(t *testing.T) {
	f := writeTempFile(t, "empty-*.pem", []byte{})

	if err := runConvertWith(f); err == nil {
		t.Error("expected error for empty input file")
	}
}

func writeTempFile(t *testing.T, pattern string, data []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), pattern)
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}
	return f.Name()
}
