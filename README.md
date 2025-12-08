# Certificate Server

A Go application that manages Let's Encrypt TLS certificates using DNS-01 challenges. It provides an HTTPS API for clients to request certificates, with automatic renewal and caching in SQLite.

## Features

- **Automated Certificate Management**: Obtains and renews Let's Encrypt certificates using the DNS-01 challenge
- **Universal DNS Provider Support**: Supports **all DNS providers** supported by lego (100+ providers including Cloudflare, AWS Route53, Google Cloud DNS, Azure, GoDaddy, Namecheap, and many more)
- **OAuth2/OIDC Authentication**: Secure API access using OAuth2/OIDC bearer tokens with automatic JWKS discovery
- **Automatic Renewal**: Background scheduler checks and renews certificates before expiration
- **Certificate Caching**: Returns cached certificates if still valid

## Installation

### Prerequisites

- Go 1.25 or later
- DNS provider credentials for any supported provider (see [Lego DNS Providers](https://go-acme.github.io/lego/dns/) for full list)
- A valid TLS certificate for the server itself (can be self-signed for testing)

### Build

```bash
go build -o cert-server
```

## Configuration

Create a `config.yaml` file based on [config.example.yaml](config.example.yaml):

```yaml
server:
  address: ":8443"
  tlsCertPath: "/etc/cert-server/server.crt"
  tlsKeyPath: "/etc/cert-server/server.key"

letsEncrypt:
  email: "admin@example.com"
  staging: true  # Use staging for testing
  dnsProvider: "cloudflare"
  dnsCredentials:
    CF_API_EMAIL: "user@example.com"
    CF_API_KEY: "your-api-key"
  renewalDays: 30
  domain: "cert-server.example.com"  # Optional

database:
  path: "/var/lib/cert-server/certs.db"

oauth2:
  issuerUrl: "https://accounts.google.com"
  audience: "your-client-id.apps.googleusercontent.com"
```

### OAuth2/OIDC Configuration

The server uses OAuth2/OIDC for authentication. You need to configure an OAuth2 provider (Google, Auth0, Azure AD, Keycloak, etc.) and provide the issuer URL and audience.

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
oauth2:
  issuerUrl: "https://accounts.google.com"
  audience: "123456789-abcdefgh.apps.googleusercontent.com"
```

1. Create a project in [Google Cloud Console](https://console.cloud.google.com)
2. Enable the Identity Platform API
3. Create OAuth 2.0 credentials (OAuth client ID)
4. Use the client ID as the `audience` value

#### Example: Auth0

```yaml
oauth2:
  issuerUrl: "https://your-tenant.auth0.com"
  audience: "https://cert-server-api"
  requiredScopes:
    - "read:certificates"
    - "write:certificates"
```

#### Example: Azure AD

```yaml
oauth2:
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

## Usage

### Start the Server

```bash
./cert-server -config config.yaml
```

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

The server runs a background scheduler that:

1. Checks for expiring certificates every 12 hours
2. Renews certificates within the configured threshold (default: 30 days)
3. Updates the database with new certificates

## Security Considerations

1. **Bearer Token**: Use a strong, randomly generated token for production
2. **HTTPS**: Always use HTTPS for the API server
3. **File Permissions**: Protect the database file and configuration file
4. **DNS Credentials**: Store DNS provider credentials securely
5. **Let's Encrypt Rate Limits**: Use staging environment for testing

### Generating a Secure Bearer Token

```bash
openssl rand -base64 32
```

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
