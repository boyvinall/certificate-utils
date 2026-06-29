package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"testing"

	"github.com/urfave/cli/v3"
)

func runConnectWith(args ...string) error {
	app := &cli.Command{
		Name:     "certificate-utils",
		Commands: []*cli.Command{connectCmd},
	}
	return app.Run(context.Background(), append([]string{"certificate-utils", "connect"}, args...))
}

func TestParseHostPort(t *testing.T) {
	tests := []struct {
		input    string
		wantHost string
		wantPort string
	}{
		{"example.com:443", "example.com", "443"},
		{"example.com:8443", "example.com", "8443"},
		{"example.com", "example.com", "443"},
		{"127.0.0.1:4433", "127.0.0.1", "4433"},
		{"[::1]:4433", "::1", "4433"},
		{"[::1]", "::1", "443"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			host, port, err := parseHostPort(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if host != tt.wantHost {
				t.Errorf("host = %q, want %q", host, tt.wantHost)
			}
			if port != tt.wantPort {
				t.Errorf("port = %q, want %q", port, tt.wantPort)
			}
		})
	}
}

func TestFormatDN(t *testing.T) {
	tests := []struct {
		name pkix.Name
		want string
	}{
		{pkix.Name{CommonName: "example.com"}, "CN=example.com"},
		{pkix.Name{CommonName: "example.com", Organization: []string{"Acme"}}, "CN=example.com, O=Acme"},
		{pkix.Name{CommonName: "foo", Organization: []string{"Org"}, Country: []string{"US"}}, "CN=foo, O=Org, C=US"},
		{pkix.Name{}, ""},
	}
	for _, tt := range tests {
		got := formatDN(tt.name)
		if got != tt.want {
			t.Errorf("formatDN(%v) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestTLSVersionName(t *testing.T) {
	tests := []struct {
		v    uint16
		want string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0x0300, "unknown (0x0300)"},
	}
	for _, tt := range tests {
		got := tlsVersionName(tt.v)
		if got != tt.want {
			t.Errorf("tlsVersionName(0x%04x) = %q, want %q", tt.v, got, tt.want)
		}
	}
}

func TestVerifyCertChain_Valid(t *testing.T) {
	ca := newTestCA(t)
	tlsCert := ca.newServerCert(t, []string{"localhost"})
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)

	if err := verifyCertChain([]*x509.Certificate{leaf}, "localhost", roots); err != nil {
		t.Errorf("expected verification to pass: %v", err)
	}
}

func TestVerifyCertChain_WrongName(t *testing.T) {
	ca := newTestCA(t)
	tlsCert := ca.newServerCert(t, []string{"localhost"})
	leaf, _ := x509.ParseCertificate(tlsCert.Certificate[0])

	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)

	if err := verifyCertChain([]*x509.Certificate{leaf}, "wrong.example.com", roots); err == nil {
		t.Error("expected verification to fail for wrong server name")
	}
}

func TestVerifyCertChain_Expired(t *testing.T) {
	ca := newTestCA(t)
	tlsCert := ca.newExpiredServerCert(t, []string{"localhost"})
	leaf, _ := x509.ParseCertificate(tlsCert.Certificate[0])

	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)

	if err := verifyCertChain([]*x509.Certificate{leaf}, "localhost", roots); err == nil {
		t.Error("expected verification to fail for expired cert")
	}
}

func TestVerifyCertChain_UntrustedCA(t *testing.T) {
	ca := newTestCA(t)
	tlsCert := ca.newServerCert(t, []string{"localhost"})
	leaf, _ := x509.ParseCertificate(tlsCert.Certificate[0])

	emptyRoots := x509.NewCertPool()

	if err := verifyCertChain([]*x509.Certificate{leaf}, "localhost", emptyRoots); err == nil {
		t.Error("expected verification to fail with untrusted CA")
	}
}

func TestVerifyCertChain_Empty(t *testing.T) {
	if err := verifyCertChain(nil, "localhost", nil); err == nil {
		t.Error("expected error for empty cert list")
	}
}

func TestLoadCertPool(t *testing.T) {
	ca := newTestCA(t)
	pool, err := loadCertPool(ca.writePEMFile(t))
	if err != nil {
		t.Fatalf("loadCertPool: %v", err)
	}
	if pool == nil {
		t.Error("expected non-nil pool")
	}
}

func TestLoadCertPool_MissingFile(t *testing.T) {
	if _, err := loadCertPool("/nonexistent/path.pem"); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadCertPool_NoCerts(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "empty-*.pem")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.WriteString("not a certificate"); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	_ = f.Close()

	if _, err := loadCertPool(f.Name()); err == nil {
		t.Error("expected error for file with no valid certificates")
	}
}

// Integration tests — connect to a local TLS server.

func TestRunConnect_Success(t *testing.T) {
	ca := newTestCA(t)
	addr := startTLSTestServer(t, ca.newServerCert(t, []string{"localhost"}))

	err := runConnectWith("--CAfile", ca.writePEMFile(t), "--servername", "localhost", addr)
	if err != nil {
		t.Errorf("expected success: %v", err)
	}
}

func TestRunConnect_SuccessWithPort(t *testing.T) {
	ca := newTestCA(t)
	addr := startTLSTestServer(t, ca.newServerCert(t, []string{"localhost"}))

	err := runConnectWith("--CAfile", ca.writePEMFile(t), "--servername", "localhost", addr)
	if err != nil {
		t.Errorf("expected success with explicit port: %v", err)
	}
}

func TestRunConnect_Insecure(t *testing.T) {
	ca := newTestCA(t)
	addr := startTLSTestServer(t, ca.newServerCert(t, []string{"localhost"}))

	if err := runConnectWith("--insecure", addr); err != nil {
		t.Errorf("expected success with --insecure: %v", err)
	}
}

func TestRunConnect_ShowCerts(t *testing.T) {
	ca := newTestCA(t)
	addr := startTLSTestServer(t, ca.newServerCert(t, []string{"localhost"}))

	err := runConnectWith("--showcerts", "--CAfile", ca.writePEMFile(t), "--servername", "localhost", addr)
	if err != nil {
		t.Errorf("expected success with --showcerts: %v", err)
	}
}

func TestRunConnect_TLS12(t *testing.T) {
	ca := newTestCA(t)
	addr := startTLSTestServer(t, ca.newServerCert(t, []string{"localhost"}))

	err := runConnectWith("--tls1_2", "--CAfile", ca.writePEMFile(t), "--servername", "localhost", addr)
	if err != nil {
		t.Errorf("expected success with --tls1_2: %v", err)
	}
}

func TestRunConnect_TLS13(t *testing.T) {
	ca := newTestCA(t)
	addr := startTLSTestServer(t, ca.newServerCert(t, []string{"localhost"}))

	err := runConnectWith("--tls1_3", "--CAfile", ca.writePEMFile(t), "--servername", "localhost", addr)
	if err != nil {
		t.Errorf("expected success with --tls1_3: %v", err)
	}
}

func TestRunConnect_WrongServerName(t *testing.T) {
	ca := newTestCA(t)
	addr := startTLSTestServer(t, ca.newServerCert(t, []string{"localhost"}))

	err := runConnectWith("--CAfile", ca.writePEMFile(t), "--servername", "wrong.example.com", addr)
	if err == nil {
		t.Error("expected failure for wrong server name")
	}
}

func TestRunConnect_UntrustedCA(t *testing.T) {
	ca := newTestCA(t)
	addr := startTLSTestServer(t, ca.newServerCert(t, []string{"localhost"}))

	// No --CAfile: system roots won't trust our test CA.
	if err := runConnectWith("--servername", "localhost", addr); err == nil {
		t.Error("expected verification failure without trusted CA")
	}
}

func TestRunConnect_ExpiredCert(t *testing.T) {
	ca := newTestCA(t)
	addr := startTLSTestServer(t, ca.newExpiredServerCert(t, []string{"localhost"}))

	err := runConnectWith("--CAfile", ca.writePEMFile(t), "--servername", "localhost", addr)
	if err == nil {
		t.Error("expected failure for expired certificate")
	}
}

func TestRunConnect_ExpiredCert_Insecure(t *testing.T) {
	ca := newTestCA(t)
	addr := startTLSTestServer(t, ca.newExpiredServerCert(t, []string{"localhost"}))

	if err := runConnectWith("--insecure", addr); err != nil {
		t.Errorf("expected --insecure to bypass expired cert: %v", err)
	}
}

func TestRunConnect_NoArg(t *testing.T) {
	if err := runConnectWith(); err == nil {
		t.Error("expected error for missing host argument")
	}
}

func TestRunConnect_ConflictingTLSFlags(t *testing.T) {
	if err := runConnectWith("--tls1_2", "--tls1_3", "localhost:443"); err == nil {
		t.Error("expected error for mutually exclusive --tls1_2 and --tls1_3")
	}
}
