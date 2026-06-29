package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v3"
)

var connectCmd = &cli.Command{
	Name:      "connect",
	Usage:     "connect to a TLS server and inspect its certificates (like openssl s_client -connect)",
	ArgsUsage: "host[:port]",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "showcerts",
			Usage: "display PEM for every certificate in the chain (default: leaf cert only)",
		},
		&cli.StringFlag{
			Name:  "servername",
			Usage: "TLS SNI server name override (default: derived from host)",
		},
		&cli.StringFlag{
			Name:  "CAfile",
			Usage: "PEM file containing trusted CA certificates",
		},
		&cli.BoolFlag{
			Name:    "insecure",
			Aliases: []string{"k"},
			Usage:   "skip certificate verification",
		},
		&cli.DurationFlag{
			Name:  "timeout",
			Value: 10 * time.Second,
			Usage: "connection timeout",
		},
		&cli.StringFlag{
			Name:  "cert",
			Usage: "client certificate file (PEM)",
		},
		&cli.StringFlag{
			Name:  "key",
			Usage: "client private key file (PEM; defaults to --cert if omitted)",
		},
		&cli.BoolFlag{
			Name:  "tls1_2",
			Usage: "negotiate TLS 1.2 only",
		},
		&cli.BoolFlag{
			Name:  "tls1_3",
			Usage: "negotiate TLS 1.3 only",
		},
	},
	Action: runConnect,
}

func runConnect(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() == 0 {
		return fmt.Errorf("missing argument: host[:port]")
	}
	if cmd.Bool("tls1_2") && cmd.Bool("tls1_3") {
		return fmt.Errorf("--tls1_2 and --tls1_3 are mutually exclusive")
	}

	host, port, err := parseHostPort(cmd.Args().Get(0))
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(host, port)

	serverName := cmd.String("servername")
	if serverName == "" {
		serverName = host
	}

	// Always connect with InsecureSkipVerify so we can display cert details
	// even when the chain is invalid. Verification is run manually below.
	tlsCfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec
	}
	switch {
	case cmd.Bool("tls1_3"):
		tlsCfg.MinVersion = tls.VersionTLS13
		tlsCfg.MaxVersion = tls.VersionTLS13
	case cmd.Bool("tls1_2"):
		tlsCfg.MinVersion = tls.VersionTLS12
		tlsCfg.MaxVersion = tls.VersionTLS12
	}

	var customRoots *x509.CertPool
	if caFile := cmd.String("CAfile"); caFile != "" {
		customRoots, err = loadCertPool(caFile)
		if err != nil {
			return fmt.Errorf("--CAfile: %w", err)
		}
	}

	if certFile := cmd.String("cert"); certFile != "" {
		keyFile := cmd.String("key")
		if keyFile == "" {
			keyFile = certFile
		}
		kp, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("loading client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{kp}
	}

	fmt.Printf("Connecting to %s (SNI: %s)... ", addr, serverName)
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: cmd.Duration("timeout")},
		"tcp", addr, tlsCfg,
	)
	if err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("connection failed: %w", err)
	}
	defer func() { _ = conn.Close() }()
	fmt.Println("connected")

	state := conn.ConnectionState()
	certs := state.PeerCertificates
	showAll := cmd.Bool("showcerts")

	// --- Certificate chain ---
	fmt.Printf("\n---\nCertificate chain (%d certificate(s))\n", len(certs))
	for i, cert := range certs {
		printChainEntry(i, cert)
		if showAll || i == 0 {
			writeCertPEM(os.Stdout, cert)
		}
	}
	fmt.Println("---")

	// --- Leaf certificate detail ---
	if len(certs) > 0 {
		fmt.Println()
		printLeafDetails(certs[0])
	}

	// --- TLS session ---
	fmt.Printf("\n---\nTLS Session\n")
	fmt.Printf("  Version: %s\n", tlsVersionName(state.Version))
	fmt.Printf("  Cipher:  %s\n", tls.CipherSuiteName(state.CipherSuite))
	if state.NegotiatedProtocol != "" {
		fmt.Printf("  ALPN:    %s\n", state.NegotiatedProtocol)
	}
	fmt.Println("---")
	fmt.Println()

	// --- Verification ---
	if cmd.Bool("insecure") {
		fmt.Println("Verification: skipped (--insecure)")
		return nil
	}
	return verifyCertChain(certs, serverName, customRoots)
}

// parseHostPort splits target into host and port, defaulting to port 443.
func parseHostPort(target string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(target)
	if err == nil {
		return
	}
	// SplitHostPort fails when there is no port (or bare IPv6).
	// Strip any stray brackets and default to 443.
	return strings.Trim(target, "[]"), "443", nil
}

func loadCertPool(file string) (*x509.CertPool, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no valid PEM certificates found in %q", file)
	}
	return pool, nil
}

func printChainEntry(idx int, cert *x509.Certificate) {
	fmt.Printf(" %d s: %s\n", idx, formatDN(cert.Subject))
	fmt.Printf("   i: %s\n", formatDN(cert.Issuer))

	remaining := time.Until(cert.NotAfter)
	note := ""
	switch {
	case remaining < 0:
		note = fmt.Sprintf(" (EXPIRED %.0f days ago)", -remaining.Hours()/24)
	case remaining < 30*24*time.Hour:
		note = fmt.Sprintf(" (expires in %.0f days — WARNING)", remaining.Hours()/24)
	}
	fmt.Printf("   v: %s → %s%s\n",
		cert.NotBefore.UTC().Format("2006-01-02"),
		cert.NotAfter.UTC().Format("2006-01-02"),
		note,
	)
}

func printLeafDetails(cert *x509.Certificate) {
	fmt.Println("Server certificate")
	fmt.Printf("  Subject:    %s\n", formatDN(cert.Subject))
	fmt.Printf("  Issuer:     %s\n", formatDN(cert.Issuer))
	fmt.Printf("  Not Before: %s\n", cert.NotBefore.UTC().Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("  Not After:  %s\n", cert.NotAfter.UTC().Format("2006-01-02 15:04:05 UTC"))

	if len(cert.DNSNames) > 0 {
		fmt.Printf("  DNS SANs:   %s\n", strings.Join(cert.DNSNames, ", "))
	}
	if len(cert.IPAddresses) > 0 {
		ips := make([]string, len(cert.IPAddresses))
		for i, ip := range cert.IPAddresses {
			ips[i] = ip.String()
		}
		fmt.Printf("  IP SANs:    %s\n", strings.Join(ips, ", "))
	}
	if len(cert.EmailAddresses) > 0 {
		fmt.Printf("  Email SANs: %s\n", strings.Join(cert.EmailAddresses, ", "))
	}

	remaining := time.Until(cert.NotAfter)
	if remaining < 0 {
		fmt.Printf("  Expires in: EXPIRED (%.0f days ago)\n", -remaining.Hours()/24)
	} else {
		fmt.Printf("  Expires in: %.0f days\n", remaining.Hours()/24)
	}
}

func writeCertPEM(w io.Writer, cert *x509.Certificate) {
	_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func verifyCertChain(certs []*x509.Certificate, serverName string, roots *x509.CertPool) error {
	if len(certs) == 0 {
		fmt.Println("Verification: FAILED — no certificates received")
		return fmt.Errorf("no certificates received from server")
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		DNSName:       serverName,
		Roots:         roots, // nil = system roots
		Intermediates: intermediates,
	})
	if err != nil {
		fmt.Printf("Verification: FAILED — %v\n", err)
		return err
	}
	fmt.Println("Verification: OK")
	return nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}

func formatDN(name pkix.Name) string {
	var parts []string
	if name.CommonName != "" {
		parts = append(parts, "CN="+name.CommonName)
	}
	for _, o := range name.Organization {
		parts = append(parts, "O="+o)
	}
	for _, ou := range name.OrganizationalUnit {
		parts = append(parts, "OU="+ou)
	}
	for _, l := range name.Locality {
		parts = append(parts, "L="+l)
	}
	for _, st := range name.Province {
		parts = append(parts, "ST="+st)
	}
	for _, c := range name.Country {
		parts = append(parts, "C="+c)
	}
	return strings.Join(parts, ", ")
}
