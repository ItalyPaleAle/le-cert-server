---
title: "Quickstart with Traefik"
nav_title: "Quickstart with Traefik"
weight: 10
---

Here's how to use le-cert-server with Traefik to automatically fetch and update certificates across your load-balanced services, without the need for Traefik Enterprise.

Benefits:

- 🔐 DNS credentials stay on le-cert-server only, not on Traefik nodes
- 🔄 All Traefik instances get the same certificate automatically
- ♻️ Certificates renew centrally and propagate to all nodes
- 🛡️ Authentication ensures only authorized nodes can fetch certificates
- 📦 Works with any number of Traefik instances (containers, VMs, or bare metal)

### 1. Deploy le-cert-server

Create a `config.yaml` file:

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

Then start le-cert-server with Docker, mounting the config file:

```bash
docker run -d \
  --name le-cert-server \
  -p 8443:8443 \
  -v $(pwd)/config.yaml:/etc/le-cert-server/config.yaml:ro \
  -v le-cert-data:/var/lib/le-cert-server \
  ghcr.io/italypaleale/le-cert-server:v0
```

> See [Installation](./installation.md) for all options to deploy le-cert-server, including standalone binaries.

### 2. Create a Traefik certificate fetcher script

```bash
#!/bin/bash
# fetch-cert.sh - Run this on each Traefik node

DOMAIN="myapp.example.com"
API_KEY="your-secure-random-key-here"
CERT_SERVER="https://cert-server.internal:8443"

# Fetch certificate from le-cert-server
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

### 3. Configure Traefik to use the certificates

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

### 4. Automate certificate refresh

Configure cron on **each Traefik node**:

```bash
# Run every 12 hours to check for renewed certificates
0 */12 * * * /usr/local/bin/fetch-cert.sh >> /var/log/cert-fetch.log 2>&1
```
