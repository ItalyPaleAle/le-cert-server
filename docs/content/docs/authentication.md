---
title: "Authentication"
nav_title: "Authentication"
weight: 30
---

le-cert-server supports two authentication methods:

1. **Pre-Shared Key (PSK) Authentication** - Simple and secure for most use cases
2. **JWT/OIDC Authentication** - Advanced scenarios with OAuth2 providers or platform identities

## Pre-Shared Key (PSK) Authentication

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
curl -X POST https://le-cert-server:8443/api/certificate \
  -H "Authorization: APIKey your-secure-random-key-here" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

> Security notice: When authenticating via PSK, _all_ callers have access to _all_ certificates. For fine-grained access control to specific certificates, use the JWT/OIDC authentication method.

## JWT/OIDC Authentication (Advanced)

For advanced scenarios, le-cert-server supports JWT token validation. This is useful when:

- Using OAuth2/OIDC providers (Auth0, Okta, Keycloak, etc.)
- Leveraging platform-managed identities (Azure Managed Identity, AWS IAM roles, Kubernetes service accounts, etc)
- Implementing fine-grained access control with scopes

Basic JWT Configuration:

```yaml
auth:
  issuerUrl: "https://your-auth-provider.com"
  audience: "your-api-audience"
  # Optional
  requiredScopes:
    - "read:certificates"
    - "write:certificates"
```

### Example: Auth0 with Client Credentials Flow

Ideal for machine-to-machine authentication:

**1. Configure Auth0:**

- Create an API in Auth0 dashboard with identifier `https://le-cert-server-api`
- Create a Machine-to-Machine application
- Authorize the application to access your API
- Define custom scopes (optional)

**2. Configure le-cert-server:**

```yaml
auth:
  issuerUrl: "https://your-tenant.auth0.com"
  audience: "https://le-cert-server-api"
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
    "audience":"https://le-cert-server-api",
    "grant_type":"client_credentials"
  }' | jq -r '.access_token')

# Request certificate
curl -X POST https://le-cert-server:8443/api/certificate \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

### Example: Azure Managed Identity

Use Azure Managed Identities to authenticate from an Azure VM, App Service, or other Azure services, without managing credentials:

**1. Configure Microsoft Entra ID:**

- Create an App Registration in Entra ID (Azure AD)
- Note the Application (client) ID: this is your "audience" value
- Assign Managed Identity to your Azure resources (VM, App Service, etc)
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
curl -X POST https://le-cert-server:8443/api/certificate \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

**Azure Managed Identity Benefits:**

- No credentials to manage or rotate
- Automatic token refresh by Azure platform
- Integrates with Azure RBAC and identity governance

### Example: AWS IAM Roles with OIDC

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
  --role-arn arn:aws:iam::ACCOUNT:role/le-cert-server-role \
  --role-session-name cert-request \
  --web-identity-token $(cat /var/run/secrets/eks.amazonaws.com/serviceaccount/token) \
  --query 'Credentials.SessionToken' \
  --output text)

# Request certificate
curl -X POST https://le--server:8443/api/certificate \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

### Example: GCP Service Account with Workload Identity

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
curl -X POST https://le-cert-server:8443/api/certificate \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

### Example: tsiam (Tailscale workload identity)

[tsiam](https://github.com/ItalyPaleAle/tsiam) issues short-lived JWTs to machines based on their Tailscale identity (a Tailscale-native equivalent of AWS IAM Roles or Azure Managed Identity). Your nodes authenticate to le-cert-server and prove who they are simply by being on your tailnet.

Because tsiam tokens are validated over standard JWT/OIDC, le-cert-server can stay on a regular TCP listener and does not itself need to run on the tailnet: it only needs network access to tsiam's OIDC discovery and JWKS endpoints (reachable over the tailnet, or publicly via Tailscale Funnel).

**1. Allow the le-cert-server audience in tsiam** (`tsiam`'s `config.yaml`):

```yaml
tokens:
  allowedAudiences:
    - "https://le-cert-server"
```

**2. Grant nodes access in your Tailscale ACL policy.** This controls which machines may request a token for the le-cert-server audience:

```json
{
  "grants": [
    {
      "src": ["tag:traefik"],
      "dst": ["tag:tsiam"],
      "app": {
        "italypaleale.me/tsiam": [
          { "allowedAudiences": ["https://le-cert-server"] }
        ]
      }
    }
  ]
}
```

**3. Configure le-cert-server** to trust tokens issued by tsiam:

```yaml
auth:
  method: jwt
  jwt:
    # tsiam's OIDC issuer URL: its MagicDNS name on your tailnet, or a Tailscale Funnel URL
    # Must match the "iss" claim in the tokens tsiam issues
    # le-cert-server discovers the JWKS endpoint via {issuerUrl}/.well-known/openid-configuration
    issuerUrl: "https://tsiam.your-tailnet.ts.net"
    # Must match the audience the client requests from tsiam (and an entry in tsiam's allowedAudiences)
    audience: "https://le-cert-server"
```

**4. Client fetches a token from tsiam, then requests a certificate:**

```bash
# From any node on the tailnet, request a token scoped to the le-cert-server audience
ACCESS_TOKEN=$(curl -s -X POST "https://tsiam/token?resource=https://le-cert-server" \
  -H "X-Tsiam: 1" | jq -r '.access_token')

# Request certificate
curl -X POST https://le-cert-server:8443/api/certificate \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```
