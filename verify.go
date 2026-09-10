package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"
)

var verifyCmd = &cli.Command{
	Name:      "verify",
	Usage:     "check that a certificate and private key match",
	ArgsUsage: "<cert-file> <key-file>",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "password",
			Aliases: []string{"p"},
			Usage:   "password for PFX/PKCS12 input",
		},
	},
	Action: runVerify,
}

func runVerify(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() != 2 {
		return fmt.Errorf("usage: certificate-utils verify <cert-file> <key-file>")
	}
	certPath := cmd.Args().Get(0)
	keyPath := cmd.Args().Get(1)
	password := cmd.String("password")

	certData, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", certPath, err)
	}
	certBundle, _, err := parseCertInput(certData, password)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", certPath, err)
	}
	if len(certBundle.certs) == 0 {
		return fmt.Errorf("%s: no certificate found", certPath)
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", keyPath, err)
	}
	privateKey, err := parsePrivateKeyInput(keyData, password)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", keyPath, err)
	}

	match, err := keyPairMatches(certBundle.certs[0].PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("comparing public keys: %w", err)
	}
	if !match {
		colorFail.Println("MISMATCH — certificate and key do not match")
		return fmt.Errorf("certificate and key do not match")
	}
	colorSuccess.Println("MATCH — certificate and key correspond")
	return nil
}

// parsePrivateKeyInput auto-detects the format of data (PEM or PFX/PKCS12)
// and returns the private key it contains, without requiring a certificate
// to be present alongside it.
func parsePrivateKeyInput(data []byte, password string) (crypto.PrivateKey, error) {
	if bytes.Contains(data, []byte("-----BEGIN")) {
		rest := data
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			switch block.Type {
			case "PRIVATE KEY":
				return x509.ParsePKCS8PrivateKey(block.Bytes)
			case "RSA PRIVATE KEY":
				return x509.ParsePKCS1PrivateKey(block.Bytes)
			case "EC PRIVATE KEY":
				return x509.ParseECPrivateKey(block.Bytes)
			}
		}
		return nil, fmt.Errorf("no private key found in PEM data")
	}

	bundle, err := parsePKCS12Bundle(data, password)
	if err != nil {
		return nil, fmt.Errorf("unrecognised format: not PEM or PFX/PKCS12")
	}
	if bundle.privateKey == nil {
		return nil, fmt.Errorf("no private key found in PKCS12 data")
	}
	return bundle.privateKey, nil
}

// keyPairMatches reports whether privKey is the private counterpart of pub.
func keyPairMatches(pub crypto.PublicKey, privKey crypto.PrivateKey) (bool, error) {
	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return false, fmt.Errorf("private key does not support signing")
	}
	privPub := signer.Public()

	switch pk := pub.(type) {
	case *rsa.PublicKey:
		otherPub, ok := privPub.(*rsa.PublicKey)
		if !ok {
			return false, nil
		}
		return pk.Equal(otherPub), nil
	case *ecdsa.PublicKey:
		otherPub, ok := privPub.(*ecdsa.PublicKey)
		if !ok {
			return false, nil
		}
		return pk.Equal(otherPub), nil
	case ed25519.PublicKey:
		otherPub, ok := privPub.(ed25519.PublicKey)
		if !ok {
			return false, nil
		}
		return pk.Equal(otherPub), nil
	default:
		return false, fmt.Errorf("unsupported public key type %T", pub)
	}
}
