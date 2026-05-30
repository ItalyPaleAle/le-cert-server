---
title: "DNS Providers"
nav_title: "DNS Providers"
weight: 30
---

le-cert-server supports **all DNS providers** supported by the lego library. The credentials are passed as environment variables that you configure in the `dnsCredentials` section.

**See the [Lego DNS Providers documentation](https://go-acme.github.io/lego/dns/) for:**

- Complete list of supported providers (100+)
- Required environment variables for each provider
- Provider-specific configuration details

The pages in this section show examples for some of the most common providers:

- [Cloudflare](/dns-providers/cloudflare)
- [AWS Route53](/dns-providers/route53)
- [DigitalOcean](/dns-providers/digitalocean)
- [Azure DNS](/dns-providers/azure)

## Using System Environment Variables

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
