package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v3"
	"golang.org/x/crypto/pkcs12"
)

type certBundle struct {
	certs      []*x509.Certificate
	privateKey crypto.PrivateKey
}

var convertCmd = &cli.Command{
	Name:      "convert",
	Usage:     "read a certificate file (or stdin), detect its format, and write it in the requested format",
	ArgsUsage: "[file]",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "format",
			Aliases: []string{"f"},
			Value:   "text",
			Usage:   "output format: text, pem, crt",
		},
		&cli.StringFlag{
			Name:    "out",
			Aliases: []string{"o"},
			Usage:   "output file (default: stdout)",
		},
		&cli.StringFlag{
			Name:    "password",
			Aliases: []string{"p"},
			Usage:   "password for PFX/PKCS12 input",
		},
	},
	Action: runConvert,
}

func runConvert(ctx context.Context, cmd *cli.Command) error {
	var (
		data []byte
		err  error
	)
	if cmd.NArg() > 0 {
		data, err = os.ReadFile(cmd.Args().Get(0))
		if err != nil {
			return fmt.Errorf("reading %s: %w", cmd.Args().Get(0), err)
		}
	} else {
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("reading stdin: %w", err)
		}
	}
	if len(data) == 0 {
		return fmt.Errorf("empty input")
	}

	password := cmd.String("password")
	bundle, inputFmt, err := parseCertInput(data, password)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Input: %s, %d certificate(s)\n", inputFmt, len(bundle.certs))

	out := io.Writer(os.Stdout)
	if outFile := cmd.String("out"); outFile != "" {
		f, ferr := os.Create(outFile)
		if ferr != nil {
			return fmt.Errorf("creating output file: %w", ferr)
		}
		defer func() { _ = f.Close() }()
		out = f
	}

	switch strings.ToLower(cmd.String("format")) {
	case "text":
		return convertWriteText(out, bundle)
	case "pem":
		return convertWritePEM(out, bundle)
	case "crt", "der":
		return convertWriteDER(out, bundle)
	default:
		return fmt.Errorf("unknown format %q — use: text, pem, crt", cmd.String("format"))
	}
}

// parseCertInput auto-detects the format of data and returns a certBundle.
func parseCertInput(data []byte, password string) (*certBundle, string, error) {
	if bytes.Contains(data, []byte("-----BEGIN")) {
		bundle, err := parsePEMBundle(data)
		if err != nil {
			return nil, "", fmt.Errorf("parsing PEM: %w", err)
		}
		return bundle, "PEM", nil
	}

	// Try raw DER X.509 certificate
	if cert, err := x509.ParseCertificate(data); err == nil {
		return &certBundle{certs: []*x509.Certificate{cert}}, "DER/CRT", nil
	}

	// Try PFX/PKCS12
	bundle, err := parsePKCS12Bundle(data, password)
	if err == nil {
		return bundle, "PFX/PKCS12", nil
	}

	return nil, "", fmt.Errorf("unrecognised format: not PEM, DER, or PFX/PKCS12")
}

func parsePEMBundle(data []byte) (*certBundle, error) {
	bundle := &certBundle{}
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parsing certificate block: %w", err)
			}
			bundle.certs = append(bundle.certs, cert)
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parsing PKCS8 private key: %w", err)
			}
			bundle.privateKey = key
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parsing RSA private key: %w", err)
			}
			bundle.privateKey = key
		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parsing EC private key: %w", err)
			}
			bundle.privateKey = key
		}
	}
	if len(bundle.certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM data")
	}
	return bundle, nil
}

func parsePKCS12Bundle(data []byte, password string) (*certBundle, error) {
	blocks, err := pkcs12.ToPEM(data, password)
	if err != nil {
		return nil, err
	}
	bundle := &certBundle{}
	for _, block := range blocks {
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parsing certificate from PKCS12: %w", err)
			}
			bundle.certs = append(bundle.certs, cert)
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parsing private key from PKCS12: %w", err)
			}
			bundle.privateKey = key
		}
	}
	if len(bundle.certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PKCS12 data")
	}
	return bundle, nil
}

// ew is a write helper that captures the first error so callers can check once at the end.
type ew struct {
	w   io.Writer
	err error
}

func (e *ew) printf(format string, args ...any) {
	if e.err == nil {
		_, e.err = fmt.Fprintf(e.w, format, args...)
	}
}

func (e *ew) println(s string) {
	if e.err == nil {
		_, e.err = fmt.Fprintln(e.w, s)
	}
}

func convertWriteText(w io.Writer, bundle *certBundle) error {
	out := &ew{w: w}
	for i, cert := range bundle.certs {
		if i > 0 {
			out.println("---")
		}
		printCertText(out, cert)
	}
	if bundle.privateKey != nil {
		out.println("---")
		out.println("Private key present")
	}
	return out.err
}

func printCertText(out *ew, cert *x509.Certificate) {
	out.printf("Subject:    %s\n", formatDN(cert.Subject))
	out.printf("Issuer:     %s\n", formatDN(cert.Issuer))
	out.printf("Not Before: %s\n", cert.NotBefore.UTC().Format("2006-01-02 15:04:05 UTC"))
	out.printf("Not After:  %s\n", cert.NotAfter.UTC().Format("2006-01-02 15:04:05 UTC"))

	remaining := time.Until(cert.NotAfter)
	if remaining < 0 {
		out.printf("Expired:    %.0f days ago\n", -remaining.Hours()/24)
	} else {
		out.printf("Expires in: %.0f days\n", remaining.Hours()/24)
	}

	if len(cert.DNSNames) > 0 {
		out.printf("DNS SANs:   %s\n", strings.Join(cert.DNSNames, ", "))
	}
	if len(cert.IPAddresses) > 0 {
		ips := make([]string, len(cert.IPAddresses))
		for i, ip := range cert.IPAddresses {
			ips[i] = ip.String()
		}
		out.printf("IP SANs:    %s\n", strings.Join(ips, ", "))
	}
	if len(cert.EmailAddresses) > 0 {
		out.printf("Email SANs: %s\n", strings.Join(cert.EmailAddresses, ", "))
	}

	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		out.printf("Key:        RSA\n")
	case x509.ECDSA:
		out.printf("Key:        ECDSA\n")
	case x509.Ed25519:
		out.printf("Key:        Ed25519\n")
	}

	if cert.IsCA {
		out.printf("CA:         yes\n")
	}
	out.printf("Serial:     %s\n", cert.SerialNumber.String())
}

func convertWritePEM(w io.Writer, bundle *certBundle) error {
	for _, cert := range bundle.certs {
		if err := pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return err
		}
	}
	if bundle.privateKey != nil {
		keyBytes, err := x509.MarshalPKCS8PrivateKey(bundle.privateKey)
		if err != nil {
			return fmt.Errorf("marshaling private key: %w", err)
		}
		if err := pem.Encode(w, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}); err != nil {
			return err
		}
	}
	return nil
}

func convertWriteDER(w io.Writer, bundle *certBundle) error {
	if len(bundle.certs) == 0 {
		return fmt.Errorf("no certificates to write")
	}
	if len(bundle.certs) > 1 {
		fmt.Fprintf(os.Stderr, "Warning: DER/CRT format supports one certificate; writing the first certificate only\n")
	}
	_, err := w.Write(bundle.certs[0].Raw)
	return err
}
