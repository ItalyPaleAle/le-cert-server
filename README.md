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
- ✅ Simple PSK authentication or optional JWT/OIDC for advanced scenarios

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
  # Set to true for testing
  staging: false
  dnsProvider: "cloudflare"
  dnsCredentials:
    CF_DNS_API_TOKEN: "your-cloudflare-token"
  renewalDays: 30

auth:
  psk:
    # Generate with: `openssl rand -base64 32`
    key: "your-secure-random-key-here"

database:
  path: "le-cert-server.db"
```

**2. Create a Traefik certificate fetcher script**:

```bash
#!/bin/bash
# fetch-cert.sh - Run this on each Traefik node

DOMAIN="myapp.example.com"
API_KEY="your-secure-random-key-here"
CERT_SERVER="https://cert-server.internal:8443"

# Fetch certificate from Certificate Server
curl -X POST "${CERT_SERVER}/api/certificate" \
  -H "Authorization: APIKey ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"domain\": \"${DOMAIN}\"}" | \
  jq -r '.certificate' > /etc/traefik/certs/${DOMAIN}.crt

# Fetch private key
curl -X POST "${CERT_SERVER}/api/certificate" \
  -H "Authorization: APIKey ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"domain\": \"${DOMAIN}\"}" | \
  jq -r '.private_key' > /etc/traefik/certs/${DOMAIN}.key

# Reload Traefik to use new certificate
docker kill -s HUP traefik
```

**3. Configure Traefik to use the certificates**:

```yaml
# traefik.yaml
entryPoints:
  websecure:
    address: ":443"

providers:
  file:
    filename: /etc/traefik/dynamic-config.yml
    watch: true

# dynamic-config.yaml
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

- 🔐 DNS credentials stay on Certificate Server only, not on Traefik nodes
- 🔄 All Traefik instances get the same certificate automatically
- ♻️ Certificates renew centrally and propagate to all nodes
- 🛡️ Authentication ensures only authorized nodes can fetch certificates
- 📦 Works with any number of Traefik instances (containers, VMs, or bare metal)

## Installation

### Using Docker (Recommended)

Use the pre-built Docker image:

```sh
docker pull ghcr.io/italypaleale/le-cert-server:v0
```

### Using Pre-built Binaries

Download the latest release for your platform from [GitHub Releases](https://github.com/ItalyPaleAle/le-cert-server/releases):

```sh
# Example for linux/amd64
wget https://github.com/ItalyPaleAle/le-cert-server/releases/latest/download/le-cert-server-linux-amd64
chmod +x le-cert-server-linux-amd64
sudo mv le-cert-server-linux-amd64 /usr/local/bin/cert-server
```

### Building from Source

If you prefer to build from source:

```bash
git clone https://github.com/ItalyPaleAle/le-cert-server.git
cd le-cert-server
go build -o le-cert-server ./cmd
```

### Request Your First Certificate

```bash
# Request a certificate using your API key
curl -k -X POST https://localhost:8443/api/certificate \
  -H "Authorization: APIKey your-secure-random-key-here" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

That's it! The certificate and private key are returned in JSON format, ready to use.

**Note:** Use `-k` flag to skip certificate verification if using self-signed certificates for testing.

---

## Detailed Configuration

### Authentication

le-cert-server supports two authentication methods:

1. **Pre-Shared Key (PSK) Authentication** - Simple and secure for most use cases
2. **JWT/OIDC Authentication** - Advanced scenarios with OAuth2 providers or platform identities

#### Pre-Shared Key (PSK) Authentication

PSK authentication is a simpler and secure option for most deployments. Configure a single API key that clients use to authenticate:

```yaml
auth:
  psk:
    key: "your-secure-random-key-here"
```

Generate a secure key:

```bash
# Generate a random 32-byte key (base64 encoded)
openssl rand -base64 32
```

Clients authenticate by passing the key in the `Authorization` header:

```bash
curl -X POST https://cert-server:8443/api/certificate \
  -H "Authorization: APIKey your-secure-random-key-here" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

#### JWT/OIDC Authentication (Advanced)

For advanced scenarios, le-cert-server supports JWT token validation. This is useful when:

- Using OAuth2/OIDC providers (Auth0, Okta, Keycloak, etc.)
- Leveraging platform-managed identities (Azure Managed Identity, AWS IAM roles, GCP Service Accounts)
- Implementing fine-grained access control with scopes

**Basic JWT Configuration:**

```yaml
auth:
  issuerUrl: "https://your-auth-provider.com"
  audience: "your-api-audience"
  # Optional
  requiredScopes:
    - "read:certificates"
    - "write:certificates"
```

##### Example: Auth0 with Client Credentials Flow

Ideal for machine-to-machine authentication:

**1. Configure Auth0:**

- Create an API in Auth0 dashboard with identifier `https://cert-server-api`
- Create a Machine-to-Machine application
- Authorize the application to access your API
- Define custom scopes (optional)

**2. Configure le-cert-server:**

```yaml
auth:
  issuerUrl: "https://your-tenant.auth0.com"
  audience: "https://cert-server-api"
  requiredScopes:
    - "request:certificates"
```

**3. Client obtains token and requests certificate:**

```bash
# Get access token using client credentials
ACCESS_TOKEN=$(curl --request POST \
  --url 'https://your-tenant.auth0.com/oauth/token' \
  --header 'content-type: application/json' \
  --data '{
    "client_id":"YOUR_CLIENT_ID",
    "client_secret":"YOUR_CLIENT_SECRET",
    "audience":"https://cert-server-api",
    "grant_type":"client_credentials"
  }' | jq -r '.access_token')

# Request certificate
curl -X POST https://cert-server:8443/api/certificate \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

##### Example: Azure Managed Identity

Use Azure Managed Identities to authenticate from an Azure VM, App Service, or other Azure services, without managing credentials:

**1. Configure Microsoft Entra ID:**

- Create an App Registration in Azure AD
- Note the Application (client) ID: this is your "audience" value
- Assign Managed Identity to your Azure resources (VM, App Service, etc.)
- Grant the Managed Identity access to the App Registration

**2. Configure le-cert-server:**

```yaml
auth:
  issuerUrl: "https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0"
  audience: "YOUR_APP_CLIENT_ID"
```

**3. Client uses Managed Identity to get token:**

```bash
# From Azure VM or App Service with Managed Identity
ACCESS_TOKEN=$(curl -s 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=YOUR_APP_CLIENT_ID' \
  -H 'Metadata: true' | jq -r '.access_token')

# Request certificate
curl -X POST https://cert-server:8443/api/certificate \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

**Azure Managed Identity Benefits:**

- No credentials to manage or rotate
- Automatic token refresh by Azure platform
- Integrates with Azure RBAC and identity governance

##### Example: AWS IAM Roles with OIDC

Use AWS IAM roles and OIDC federation for credential-free authentication:

**1. Set up OIDC Provider in AWS IAM:**

- Configure an OIDC identity provider pointing to your auth server
- Create an IAM role with trust policy for the OIDC provider
- EC2 instances or ECS tasks assume this role

**2. Configure le-cert-server:**

```yaml
auth:
  issuerUrl: "https://your-oidc-provider.com"
  audience: "sts.amazonaws.com"
```

**3. Client uses AWS STS to exchange IAM credentials for OIDC token:**

```bash
# Get OIDC token from AWS STS
ACCESS_TOKEN=$(aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::ACCOUNT:role/cert-server-role \
  --role-session-name cert-request \
  --web-identity-token $(cat /var/run/secrets/eks.amazonaws.com/serviceaccount/token) \
  --query 'Credentials.SessionToken' \
  --output text)

# Request certificate
curl -X POST https://cert-server:8443/api/certificate \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

##### Example: GCP Service Account with Workload Identity

Use GCP Workload Identity for GKE workloads or service accounts:

**1. Set up Workload Identity:**

- Enable Workload Identity on your GKE cluster
- Create a service account and bind it to Kubernetes service account
- Grant the service account appropriate IAM roles

**2. Configure le-cert-server:**

```yaml
auth:
  issuerUrl: "https://accounts.google.com"
  audience: "YOUR_CLIENT_ID.apps.googleusercontent.com"
```

**3. Client uses GCP metadata service to get identity token:**

```bash
# From GKE pod with Workload Identity
ACCESS_TOKEN=$(curl -s "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=YOUR_CLIENT_ID.apps.googleusercontent.com" \
  -H "Metadata-Flavor: Google")

# Request certificate
curl -X POST https://cert-server:8443/api/certificate \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
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
  CF_DNS_API_TOKEN: "your-dns-api-token"
  # OR use API key (not recommended):
  # CF_API_EMAIL: "user@example.com"
  # CF_API_KEY: "your-api-key"
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

#### Request a Certificate

**Using PSK Authentication:**

```bash
curl -X POST https://localhost:8443/api/certificate \
  -H "Authorization: APIKey your-secure-random-key-here" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

**Using JWT Authentication:**

```bash
# First obtain a token from your OAuth2 provider (see Authentication section)
ACCESS_TOKEN="your-jwt-token"

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
  -H "Authorization: APIKey your-secure-random-key-here" \
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

le-cert-server is designed with security as a priority:

- **Centralized Credentials**: DNS provider credentials are stored only on the Certificate Server, not on client nodes
- **Flexible Authentication**: Simple PSK for most use cases, or JWT/OIDC for advanced scenarios
- **HTTPS API**: All communication is encrypted with TLS
- **Audit Trail**: All certificate requests and renewals are logged
- **Least Privilege**: Client nodes only need API access, not DNS provider credentials

### Security Checklist

- ✅ Use strong, randomly-generated API keys (PSK) or JWT authentication
- ✅ Deploy le-cert-server on a trusted, isolated network segment
- ✅ Use production Let's Encrypt (not staging) only after testing
- ✅ Protect the config file with appropriate file permissions (600 or 640)
- ✅ Use a dedicated service account for the le-cert-server process
- ✅ Enable firewall rules to restrict API access to known client IPs if possible
- ✅ Regularly backup the SQLite database to preserve certificate cache
- ✅ Monitor logs for unauthorized access attempts
- ✅ Rotate API keys periodically
- ✅ Use TLS certificates for the server (can be self-signed for internal use)

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

func requestCertificate(domain, serverURL, apiKey string) (*CertResponse, error) {
    reqBody, _ := json.Marshal(CertRequest{Domain: domain})

    req, _ := http.NewRequest("POST", serverURL+"/api/certificate", bytes.NewBuffer(reqBody))
    req.Header.Set("Authorization", "APIKey "+apiKey)
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

def request_certificate(domain, server_url, api_key):
    headers = {
        "Authorization": f"APIKey {api_key}",
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
cert = request_certificate("example.com", "https://localhost:8443", "your-api-key")
print(cert["certificate"])
```

### cURL

```bash
#!/bin/bash

DOMAIN="example.com"
SERVER_URL="https://localhost:8443"
API_KEY="your-secure-random-key-here"

# Request and extract certificate
curl -k -X POST "${SERVER_URL}/api/certificate" \
  -H "Authorization: APIKey ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"domain\": \"${DOMAIN}\"}" \
  | jq -r '.certificate' > certificate.pem

# Request and extract private key
curl -k -X POST "${SERVER_URL}/api/certificate" \
  -H "Authorization: APIKey ${API_KEY}" \
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

Use the pre-built Docker image from GitHub Container Registry:

```bash
# Pull the latest image
docker pull ghcr.io/italypaleale/le-cert-server:v0

# Run the container
docker run -d \
  --name cert-server \
  -p 8443:8443 \
  -v /var/lib/cert-server:/var/lib/cert-server \
  -v /etc/cert-server/config.yaml:/etc/cert-server/config.yaml:ro \
  ghcr.io/italypaleale/le-cert-server:v0
```

**Docker Compose Example:**

```yaml
version: '3.8'

services:
  cert-server:
    image: ghcr.io/italypaleale/le-cert-server:v0
    container_name: cert-server
    restart: unless-stopped
    ports:
      - "8443:8443"
    volumes:
      - ./config.yaml:/etc/cert-server/config.yaml:ro
      - cert-data:/var/lib/cert-server
    environment:
      # Optional: override config with environment variables
      - CF_DNS_API_TOKEN=${CF_DNS_API_TOKEN}

volumes:
  cert-data:
```

Start with:

```bash
docker-compose up -d
```

## License

MIT License - See LICENSE file for details
