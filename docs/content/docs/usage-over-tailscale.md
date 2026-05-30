---
title: "Usage over Tailscale"
nav_title: "Usage over Tailscale"
weight: 40
---

le-cert-server can run directly on your [Tailscale](https://tailscale.com) network using an embedded `tsnet` node, instead of listening on a regular TCP socket. This is a convenient way to deploy it on a private network without exposing it publicly.

Benefits:

- The API is only reachable from machines on your tailnet—no public exposure required
- HTTPS is served automatically using Tailscale-provided certificates, so there's nothing to configure or renew for the API listener itself
- Clients authenticate using their Tailscale node identity—no pre-shared keys or tokens to distribute
- Fine-grained, per-domain authorization is controlled centrally from your Tailscale ACL policy

## Configuration

Set `server.listener` to `tsnet` and configure the `server.tsnet` section. When the `tsnet` listener is used:

- The server listens on a Tailscale netstack and always serves HTTPS using Tailscale-provided certificates
- `server.bind` and `server.tls` are ignored
- The default port is `443`

```yaml
# config.yaml
server:
  listener: "tsnet"
  tsnet:
    # Hostname for this node on your tailnet
    hostname: "le-cert-server"
    # Auth key used only on first startup to join the tailnet
    # If empty, tsnet relies on existing state in the state directory
    authKey: "tskey-auth-xxxxx"
    # Directory where tsnet stores its state
    # Defaults to a folder next to the loaded config file
    #stateDir: ""
    # If true, the node is ephemeral (not persisted in the tailnet)
    #ephemeral: false

# Use the built-in "tsnet" auth method, where client are authenticated using the node identity in the tailnet
# Permissions are configured using the standard Tailscale ACL policy
auth:
  method: "tsnet"

# Configure Let's Encrypt and the database as per usual
letsEncrypt:
  email: "admin@example.com"
  dnsProvider: "cloudflare"
  dnsCredentials:
    dnsAPIToken: "your-cloudflare-token"
  renewalDays: 30

database:
  path: "le-cert-server.db"
```

The `authKey` is only used on first startup to join the tailnet (or when the node key expires). Generate one in the [Tailscale admin console](https://login.tailscale.com/admin/settings/keys). Once the node has joined, its state is persisted and the key is no longer needed.

## Authentication with Tailscale identity

When running over `tsnet`, you can authenticate callers by their Tailscale node identity by setting `auth.method` to `tsnet`. This method is only available when `server.listener` is also set to `tsnet`.

With Tailscale identity authentication:

- Callers do **not** send an `Authorization` header. le-cert-server determines the caller's identity from the tailnet connection itself, so the identity cannot be forged.
- Authorization to request certificates for specific domains is granted in your Tailscale ACL policy, using the app capability `italypaleale.me/le-cert-server`.
- A node that has not been granted any domains is rejected.

In the Tailscale ACL editor, grant nodes the `italypaleale.me/le-cert-server` capability with the list of allowed domains:

```json
{
  "grants": [
    {
      "src": ["*"],
      "dst": ["le-cert-server"],
      "app": {
        "italypaleale.me/le-cert-server": [
          { "domains": ["example.com"] },
          { "domains": ["*.example2.com"] }
        ]
      }
    }
  ]
}
```

- `src` controls which machines may request certificates (use `*` for any node, or restrict to specific tags such as `tag:traefik`)
- `dst` is the le-cert-server node
- Each entry under the capability lists the `domains` those nodes are allowed to request, including wildcards such as `*.example2.com`

## Requesting a certificate

From any authorized node on your tailnet, call the API over HTTPS using the node's hostname. No `Authorization` header is needed—the request is authenticated by your Tailscale identity:

```bash
curl -X POST https://le-cert-server.your-tailnet.ts.net/api/certificate \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

The domain must be covered by the grants assigned to the calling node, otherwise the request is rejected.
