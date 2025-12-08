# le-cert-server

Secure, centralized Let's Encrypt certificate management for multiple servers and distributed systems.

- **Load-balanced applications** that need the same certificate on multiple nodes.  
   When using Traefik, le-cert-server is an alternative to Traefik Enterprise for using Let's Encrypt across multiple instances.
- **Edge servers** that need to fetch certificates dynamically
- **Development teams** that want to simplify certificate management across environments

le-cert-server uses the DNS-01 challenge to prove ownership of a domain and ask Let's Encrypt for a TLS certficate (*note: other challenges, including HTTP-01 are not supported*).

## Why le-cert-server

Managing TLS certificates across multiple servers is challenging:

- 🔄 Manual synchronization between nodes leads to errors and downtime
- 🔐 DNS credentials scattered across different machines increase security risks
- ⏰ Certificate renewals require coordination or risk service interruptions
- 🛡️ Security policies are harder to enforce in distributed environments

le-cert-server solves these problems by providing a single, secure source of truth for your Let's Encrypt certificates. Request certificates from any server, and they're automatically obtained, renewed, and ready to use, all while keeping your DNS credentials safe in one place.

## How It Works

1. **Deploy once**: Run Certificate Server on a trusted machine with your DNS provider credentials
2. **Request from anywhere**: Your applications call the API to request certificates for their domains
3. **Get secure certificates**: Certificates are obtained via Let's Encrypt using DNS-01 validation
4. **Automatic renewal**: Certificates are renewed before expiration—no manual intervention needed
5. **OAuth2 security**: All API access is secured with industry-standard OAuth2/OIDC authentication

Benefits:

- ✅ Automated certificate lifecycle management
- ✅ Support for 100+ DNS providers (Cloudflare, AWS Route53, Azure DNS, and more)
- ✅ Centralized, secure credential storage
- ✅ Wildcard certificate support via DNS-01 challenge
- ✅ Built-in caching to avoid rate limits
- ✅ Optional OAuth2/OIDC authentication for API security

## Quick Example: Using with Traefik

Here's how to use Certificate Server with Traefik to automatically fetch and update certificates across your load-balanced services, without the need for Traefik Enterprise:

**1. Deploy Certificate Server** (one-time setup):

```yaml
# config.yaml
server:
  bind: "0.0.0.0"
  port: 8443

letsEncrypt:
  email: "admin@example.com"
  staging: false
  dnsProvider: "cloudflare"
  dnsCredentials:
    CF_DNS_API_TOKEN: "your-cloudflare-token"
  renewalDays: 30

auth:
  issuerUrl: "https://accounts.google.com"
  audience: "your-client-id.apps.googleusercontent.com"

database:
  path: "/var/lib/cert-server/certs.db"
```

**2. Create a Traefik certificate fetcher script**:

```bash
#!/bin/bash
# fetch-cert.sh - Run this on each Traefik node

DOMAIN="myapp.example.com"
ACCESS_TOKEN=$(gcloud auth print-identity-token --audiences="your-client-id.apps.googleusercontent.com")
CERT_SERVER="https://cert-server.internal:8443"

# Fetch certificate from Certificate Server
curl -X POST "${CERT_SERVER}/api/certificate" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"domain\": \"${DOMAIN}\"}" | \
  jq -r '.certificate' > /etc/traefik/certs/${DOMAIN}.crt

# Fetch private key
curl -X POST "${CERT_SERVER}/api/certificate" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"domain\": \"${DOMAIN}\"}" | \
  jq -r '.private_key' > /etc/traefik/certs/${DOMAIN}.key

# Reload Traefik to use new certificate
docker kill -s HUP traefik
```

**3. Configure Traefik to use the certificates**:

```yaml
# traefik.yml
entryPoints:
  websecure:
    address: ":443"

providers:
  file:
    filename: /etc/traefik/dynamic.yml
    watch: true

# dynamic.yml
tls:
  certificates:
    - certFile: /etc/traefik/certs/myapp.example.com.crt
      keyFile: /etc/traefik/certs/myapp.example.com.key
```

**4. Automate certificate refresh** (cron on each Traefik node):

```bash
# Run every 12 hours to check for renewed certificates
0 */12 * * * /usr/local/bin/fetch-cert.sh >> /var/log/cert-fetch.log 2>&1
```

**Benefits of this setup:**

- 🔐 DNS credentials stay on Certificate Server only—not on Traefik nodes
- 🔄 All Traefik instances get the same certificate automatically
- ♻️ Certificates renew centrally and propagate to all nodes
- 🛡️ OAuth2 authentication ensures only authorized nodes can fetch certificates
- 📦 Works with any number of Traefik instances (containers, VMs, or bare metal)

## Installation

### Prerequisites

- Go 1.25 or later
- DNS provider credentials for any supported provider (see [Lego DNS Providers](https://go-acme.github.io/lego/dns/) for full list)
- An OAuth2/OIDC provider for API authentication (Google, Auth0, Azure AD, Keycloak, etc.)
- A valid TLS certificate for the server itself (can be self-signed for testing)

### Build

```bash
go build -o cert-server
```

## Getting Started

### Quick Configuration

Create a `config.yaml` file (see [config.example.yaml](config.example.yaml) for full options):

```yaml
server:
  bind: "0.0.0.0"
  port: 8443

letsEncrypt:
  email: "admin@example.com"
  staging: true  # Use staging for testing, false for production
  dnsProvider: "cloudflare"
  dnsCredentials:
    CF_DNS_API_TOKEN: "your-cloudflare-token"
  renewalDays: 30

database:
  path: "/var/lib/cert-server/certs.db"

auth:
  issuerUrl: "https://accounts.google.com"
  audience: "your-client-id.apps.googleusercontent.com"
```

### Start the Server

```bash
./cert-server -config config.yaml
```

The server will:
- Start an HTTPS API on port 8443
- Connect to your OAuth2 provider for authentication
- Begin monitoring certificates for automatic renewal

### Request Your First Certificate

```bash
# Get an access token from your OAuth2 provider
ACCESS_TOKEN=$(gcloud auth print-identity-token --audiences="your-client-id.apps.googleusercontent.com")

# Request a certificate
curl -X POST https://localhost:8443/api/certificate \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

That's it! The certificate and private key are returned in JSON format, ready to use.

---

## Detailed Configuration

### OAuth2/OIDC Authentication

The server uses OAuth2/OIDC for secure API access. Configure any OAuth2 provider (Google, Auth0, Azure AD, Keycloak, etc.).

#### Supported OAuth2 Providers

Any OAuth2/OIDC compliant provider is supported:

- **Google**: `https://accounts.google.com`
- **Auth0**: `https://your-tenant.auth0.com`
- **Azure AD**: `https://login.microsoftonline.com/{tenant-id}/v2.0`
- **Keycloak**: `https://keycloak.example.com/realms/your-realm`
- **Okta**: `https://your-domain.okta.com`
- **GitHub**: Not directly supported (requires OAuth2 to OIDC bridge)

#### Example: Google OAuth2

```yaml
auth:
  issuerUrl: "https://accounts.google.com"
  audience: "123456789-abcdefgh.apps.googleusercontent.com"
```

1. Create a project in [Google Cloud Console](https://console.cloud.google.com)
2. Enable the Identity Platform API
3. Create OAuth 2.0 credentials (OAuth client ID)
4. Use the client ID as the `audience` value

#### Example: Auth0

```yaml
auth:
  issuerUrl: "https://your-tenant.auth0.com"
  audience: "https://cert-server-api"
  requiredScopes:
    - "read:certificates"
    - "write:certificates"
```

#### Example: Azure AD

```yaml
auth:
  issuerUrl: "https://login.microsoftonline.com/your-tenant-id/v2.0"
  audience: "api://cert-server"
```

### DNS Provider Configuration

This server supports **all DNS providers** supported by the lego library. The credentials are passed as environment variables that you configure in the `dnsCredentials` section.

**See the [Lego DNS Providers documentation](https://go-acme.github.io/lego/dns/) for:**
- Complete list of supported providers (100+)
- Required environment variables for each provider
- Provider-specific configuration details

#### Example: Cloudflare

```yaml
dnsProvider: "cloudflare"
dnsCredentials:
  CF_API_EMAIL: "user@example.com"
  CF_API_KEY: "your-api-key"
  # OR use API token (recommended):
  # CF_DNS_API_TOKEN: "your-dns-api-token"
```

#### Example: AWS Route53

```yaml
dnsProvider: "route53"
dnsCredentials:
  AWS_ACCESS_KEY_ID: "your-access-key"
  AWS_SECRET_ACCESS_KEY: "your-secret-key"
  AWS_REGION: "us-east-1"
```

#### Example: DigitalOcean

```yaml
dnsProvider: "digitalocean"
dnsCredentials:
  DO_AUTH_TOKEN: "your-token"
```

#### Example: Azure DNS

```yaml
dnsProvider: "azure"
dnsCredentials:
  AZURE_CLIENT_ID: "your-client-id"
  AZURE_CLIENT_SECRET: "your-client-secret"
  AZURE_SUBSCRIPTION_ID: "your-subscription-id"
  AZURE_TENANT_ID: "your-tenant-id"
  AZURE_RESOURCE_GROUP: "your-resource-group"
```

#### Using System Environment Variables

Alternatively, you can omit `dnsCredentials` from the config file and set the required environment variables directly in your system:

```yaml
letsEncrypt:
  dnsProvider: "cloudflare"
  # No dnsCredentials needed if env vars are already set
```

Then start the server with environment variables:

```bash
export CF_DNS_API_TOKEN="your-token"
./cert-server -config config.yaml
```

## API Reference

### API Endpoints

#### Health Check

```bash
curl https://localhost:8443/health
```

**Response:**

```json
{
  "status": "healthy",
  "time": "2025-01-20T22:00:00Z"
}
```

#### Obtaining an Access Token

Before making API requests, you need to obtain an OAuth2 access token from your configured provider.

**Example with Google:**

```bash
# Use gcloud or OAuth2 client library to get a token
ACCESS_TOKEN=$(gcloud auth print-identity-token --audiences="your-client-id.apps.googleusercontent.com")
```

**Example with Auth0:**

```bash
curl --request POST \
  --url 'https://your-tenant.auth0.com/oauth/token' \
  --header 'content-type: application/json' \
  --data '{
    "client_id":"YOUR_CLIENT_ID",
    "client_secret":"YOUR_CLIENT_SECRET",
    "audience":"https://cert-server-api",
    "grant_type":"client_credentials"
  }' | jq -r '.access_token'
```

#### Request a Certificate

```bash
curl -X POST https://localhost:8443/api/certificate \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

**Response:**

```json
{
  "domain": "example.com",
  "certificate": "-----BEGIN CERTIFICATE-----\n...",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...",
  "issuer_cert": "-----BEGIN CERTIFICATE-----\n...",
  "not_before": "2025-01-01T00:00:00Z",
  "not_after": "2025-04-01T00:00:00Z",
  "cached": false
}
```

#### Renew a Certificate

```bash
curl -X POST https://localhost:8443/api/certificate/renew \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

## Automatic Renewal

**Never worry about certificate expiration again.** Certificate Server handles renewal automatically:

- 🔄 Background scheduler checks for expiring certificates every 12 hours
- ⏰ Renews certificates within the configured threshold (default: 30 days before expiration)
- 💾 Updates the database with fresh certificates automatically
- 📢 Clients automatically receive renewed certificates on their next API request

**How it helps you:**
- No manual renewal workflows or reminders needed
- Prevents service outages from expired certificates
- Works seamlessly across all your servers—renew once, available everywhere

## Security & Best Practices

Certificate Server is designed with security as a priority:

- **Centralized Credentials**: DNS provider credentials are stored only on the Certificate Server, not on client nodes
- **OAuth2/OIDC Authentication**: Industry-standard authentication with automatic token validation using JWKS
- **HTTPS API**: All communication is encrypted with TLS
- **Audit Trail**: All certificate requests and renewals are logged
- **Least Privilege**: Client nodes only need API access, not DNS provider credentials

### Security Checklist

- ✅ Use OAuth2/OIDC with a trusted provider (not simple bearer tokens)
- ✅ Deploy Certificate Server on a trusted, isolated network segment
- ✅ Use production Let's Encrypt (not staging) only after testing
- ✅ Protect the config file with appropriate file permissions (600 or 640)
- ✅ Use a dedicated service account for the Certificate Server process
- ✅ Enable firewall rules to restrict API access to known client IPs if possible
- ✅ Regularly backup the SQLite database to preserve certificate cache
- ✅ Monitor logs for unauthorized access attempts

## API Client Examples

### Go

```go
package main

import (
    "bytes"
    "crypto/tls"
    "encoding/json"
    "fmt"
    "net/http"
)

type CertRequest struct {
    Domain string `json:"domain"`
}

type CertResponse struct {
    Domain      string `json:"domain"`
    Certificate string `json:"certificate"`
    PrivateKey  string `json:"private_key"`
}

func requestCertificate(domain, serverURL, token string) (*CertResponse, error) {
    reqBody, _ := json.Marshal(CertRequest{Domain: domain})

    req, _ := http.NewRequest("POST", serverURL+"/api/certificate", bytes.NewBuffer(reqBody))
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Content-Type", "application/json")

    // For self-signed certs in testing, use InsecureSkipVerify
    client := &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        },
    }

    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var certResp CertResponse
    json.NewDecoder(resp.Body).Decode(&certResp)
    return &certResp, nil
}
```

### Python

```python
import requests

def request_certificate(domain, server_url, token):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    data = {"domain": domain}

    # For self-signed certs in testing, use verify=False
    response = requests.post(
        f"{server_url}/api/certificate",
        headers=headers,
        json=data,
        verify=False  # Remove in production
    )

    return response.json()

# Example usage
cert = request_certificate("example.com", "https://localhost:8443", "your-token")
print(cert["certificate"])
```

### cURL

```bash
#!/bin/bash

DOMAIN="example.com"
SERVER_URL="https://localhost:8443"
TOKEN="your-secret-token"

# Request and extract certificate
curl -k -X POST "${SERVER_URL}/api/certificate" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"domain\": \"${DOMAIN}\"}" \
  | jq -r '.certificate' > certificate.pem

# Request and extract private key
curl -k -X POST "${SERVER_URL}/api/certificate" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"domain\": \"${DOMAIN}\"}" \
  | jq -r '.private_key' > private_key.pem

echo "Certificate saved to certificate.pem"
echo "Private key saved to private_key.pem"
```

## Production Deployment

### Systemd Service

Create `/etc/systemd/system/cert-server.service`:

```ini
[Unit]
Description=Certificate Server
After=network.target

[Service]
Type=simple
User=cert-server
Group=cert-server
WorkingDirectory=/opt/cert-server
ExecStart=/opt/cert-server/cert-server -config /etc/cert-server/config.yaml
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable cert-server
sudo systemctl start cert-server
sudo systemctl status cert-server
```

### Docker

Create a `Dockerfile`:

```dockerfile
FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN go build -o cert-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/cert-server /usr/local/bin/
COPY config.yaml /etc/cert-server/config.yaml
EXPOSE 8443
CMD ["cert-server", "-config", "/etc/cert-server/config.yaml"]
```

Build and run:

```bash
docker build -t cert-server .
docker run -d -p 8443:8443 \
  -v /var/lib/cert-server:/var/lib/cert-server \
  -v /etc/cert-server:/etc/cert-server \
  cert-server
```

## License

MIT License - See LICENSE file for details
