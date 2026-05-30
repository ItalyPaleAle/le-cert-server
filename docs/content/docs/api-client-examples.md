---
title: "API Client Examples"
nav_title: "API Client Examples"
weight: 60
---

## API Endpoints

### Request a Certificate

**Using PSK Authentication:**

```bash
curl -X POST https://le-cert-server:8443/api/certificate \
  -H "Authorization: APIKey your-secure-random-key-here" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

**Using JWT Authentication:**

First obtain a token from your OAuth2 provider (see [Authentication](./authentication.md))

```bash
ACCESS_TOKEN="your-jwt-token"

curl -X POST https://le-cert-server:8443/api/certificate \
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

### Renew a Certificate

```bash
curl -X POST https://le-cert-server:8443/api/certificate/renew \
  -H "Authorization: APIKey your-secure-random-key-here" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

## Go

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

func requestCertificate(domain string, serverURL string, apiKey string) (*CertResponse, error) {
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

## Python

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
cert = request_certificate("example.com", "https://le-cert-server:8443", "your-api-key")
print(cert["certificate"])
```

## cURL

```bash
#!/bin/bash

DOMAIN="example.com"
SERVER_URL="https://le-cert-server:8443"
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
