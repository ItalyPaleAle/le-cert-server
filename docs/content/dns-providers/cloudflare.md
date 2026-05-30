---
title: "Cloudflare"
nav_title: "Cloudflare"
weight: 10
---

```yaml
dnsProvider: "cloudflare"
dnsCredentials:
  CF_DNS_API_TOKEN: "your-dns-api-token"
  # OR use API key (not recommended):
  # CF_API_EMAIL: "user@example.com"
  # CF_API_KEY: "your-api-key"
```

See the [Lego Cloudflare documentation](https://go-acme.github.io/lego/dns/cloudflare/) for the full list of supported environment variables.
