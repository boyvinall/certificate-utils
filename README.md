# certificate-utils

A CLI for inspecting and converting TLS certificates — no more hunting for the right `openssl` flags.

## Installation

```sh
go install github.com/boyvinall/certificate-utils@latest  # build and install to $GOPATH/bin
```

Or build from source:

```sh
make build  # produces bin/certificate-utils
```

## Commands

### `connect` — inspect a live TLS server

Connect to a server and display its certificate chain, TLS session details, and verification result.

```sh
certificate-utils connect example.com                                           # connects to port 443
certificate-utils connect example.com:8443                                      # specify port
certificate-utils connect --showcerts example.com:8443                          # print PEM for all presented certs
certificate-utils connect --showcerts=false example.com:8443                    # don't print leaf PEM
certificate-utils connect --servername example.com someotherserver.com:8443     # override SNI
certificate-utils connect --servername example.com --servername example2.com someotherserver.com:8443  # multiple SNI, check each
```

**Options**

| Flag | Description |
|------|-------------|
| `--showcerts` | Print PEM for every cert in the chain (default: leaf only), use `--showcerts=false` to also disable printing leaf cert |
| `--servername` | Override the TLS SNI name, can be specified multiple times |
| `--CAfile` | PEM file of trusted CA certificates |
| `--insecure, -k` | Skip certificate verification |
| `--timeout` | Connection timeout (default: 10s) |
| `--cert` | Client certificate file (PEM) |
| `--key` | Client private key file (PEM; defaults to `--cert`) |
| `--tls1_2` | Negotiate TLS 1.2 only |
| `--tls1_3` | Negotiate TLS 1.3 only |

---

### `convert` — detect format and convert

Reads a certificate file (or stdin), auto-detects the format, and writes it out in the requested format.

**Detected input formats:** PEM, DER/CRT (binary X.509), PFX/PKCS12

**Output formats:** `text` (default), `pem`, `crt`

```sh
# Inspect any certificate file — format is detected automatically
certificate-utils convert cert.pem
certificate-utils convert cert.crt
certificate-utils convert cert.pfx --password secret

# Convert between formats
certificate-utils convert cert.pfx --password secret --format pem
certificate-utils convert cert.pem --format crt --out cert.crt

# Pipe from stdin
openssl s_client -connect example.com:443 </dev/null 2>/dev/null | certificate-utils convert
```

**Options**

| Flag | Description |
|------|-------------|
| `--format, -f` | Output format: `text`, `pem`, `crt` (default: `text`) |
| `--out, -o` | Write output to a file instead of stdout |
| `--password, -p` | Password for PFX/PKCS12 input |

### `verify` — check a certificate and key match

Checks that a certificate's public key corresponds to a given private key — useful before
loading a cert/key pair into a server.

```sh
certificate-utils verify cert.pem cert.key
certificate-utils verify cert.pfx server.key --password secret
```

**Options**

| Flag | Description |
|------|-------------|
| `--password, -p` | Password for PFX/PKCS12 input |

### Global options

| Flag | Description |
|------|-------------|
| `--level, -l` | Log level: `debug`, `info`, `warn`, `error` (default: `info`) |
