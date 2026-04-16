# ACME Client

A fully functional [ACME (RFC 8555)](https://datatracker.ietf.org/doc/html/rfc8555) protocol client that automates TLS certificate acquisition from any ACME-compliant Certificate Authority (e.g. Let's Encrypt, Pebble).

## Features

- **Full ACME lifecycle** — account registration, order creation, challenge resolution, CSR generation, certificate retrieval
- **Dual challenge support** — HTTP-01 and DNS-01 domain validation
- **Cryptographic signing** — ECDSA (ES256) with JWS-formatted requests and proper nonce management
- **Live HTTPS server** — serves the obtained certificate immediately after issuance
- **Multi-domain support** — issue certificates with multiple Subject Alternative Names (SANs)

## Requirements

- Python 3.8+
- [`dnslib`](https://pypi.org/project/dnslib/) (`pip install -r requirements.txt`)

## Usage

```bash
python -m acme_client <challenge_type> --dir <acme_dir_url> --record <ipv4_addr> --domain <domain> [--domain <domain2> ...]
```

| Argument | Description |
|---|---|
| `challenge_type` | `http01` or `dns01` |
| `--dir` | URL of the ACME directory endpoint |
| `--record` | IPv4 address to use in DNS A records |
| `--domain` | Domain(s) to include in the certificate (repeatable) |

### Example

```bash
# HTTP-01 challenge
python -m acme_client http01 \
  --dir https://acme-v02.api.letsencrypt.org/directory \
  --record 1.2.3.4 \
  --domain example.com \
  --domain www.example.com

# DNS-01 challenge
python -m acme_client dns01 \
  --dir https://acme-v02.api.letsencrypt.org/directory \
  --record 1.2.3.4 \
  --domain example.com
```

## Architecture

| Component | Port | Role |
|---|---|---|
| HTTP-01 challenge server | 5002 | Serves `/.well-known/acme-challenge/` tokens |
| DNS-01 challenge server | 10053 | Responds to `_acme-challenge` TXT queries |
| HTTPS certificate server | 5001 | Serves content over TLS using the issued certificate |
| Shutdown server | 5003 | Graceful shutdown endpoint |

## Output

After a successful run, two files are written to the working directory:

- `certificate.pem` — the issued certificate chain
- `private_key.pem` — the corresponding EC private key

## License

MIT
