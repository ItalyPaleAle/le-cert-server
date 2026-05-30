---
title: "le-cert-server"
nav_title: "Introduction"
weight: 10
---

Secure, centralized Let's Encrypt certificate management for multiple servers and distributed systems.

- **Load-balanced applications** that need the same certificate on multiple nodes.  
   When using [Traefik](https://github.com/traefik/traefik), le-cert-server is an alternative to Traefik Enterprise for using Let's Encrypt across multiple instances.
- **Edge servers** that need to fetch certificates dynamically
- **Development teams** that want to simplify certificate management across environments

le-cert-server uses the DNS-01 challenge to prove ownership of a domain and ask Let's Encrypt for a TLS certficate (*note: other challenges, including HTTP-01 are not supported*).

## Why le-cert-server

Managing TLS certificates across multiple servers is challenging:

- 🔄 Manual synchronization between nodes leads to errors and downtime
- 🔐 DNS credentials scattered across different machines increase security risks
- ⏰ Certificate renewals require coordination or risk service interruptions
- 🛡️ Security policies are harder to enforce in distributed environments

le-cert-server solves these problems by providing a single and secure source of truth for your Let's Encrypt certificates. Request certificates from any server, and they're automatically obtained, renewed, and ready to use, all while keeping your DNS credentials safe in one place.

## How It Works

1. **Deploy once**: Run Certificate Server on a trusted machine with your DNS provider credentials
2. **Request from anywhere**: Your applications call the API to request certificates for their domains
3. **Get secure certificates**: Certificates are obtained via Let's Encrypt using DNS-01 validation
4. **Automatic renewal**: Certificates are renewed before expiration—no manual intervention needed
5. **OAuth2 security**: All API access is secured with industry-standard OAuth2/OIDC authentication

Benefits:

- ✅ Automated certificate lifecycle management
- ✅ Support for 100+ DNS providers (Cloudflare, AWS Route53, Azure DNS, NS1, and many more)
- ✅ Centralized, secure credential storage
- ✅ Wildcard certificate support via DNS-01 challenge
- ✅ Built-in caching to avoid rate limits
- ✅ Simple PSK authentication or optional JWT/OIDC for advanced scenarios

## Automatic Renewal

le-cert-server handles renewal automatically, so you don't have to worry about it again:

- 🔄 Background scheduler checks for expiring certificates every 12 hours
- ⏰ Renews certificates within the configured threshold (default: 30 days before expiration)
- 💾 Updates the database with fresh certificates automatically
- 📢 Clients automatically receive renewed certificates on their next API request

## Start here

- [Quickstart with Traefik](/docs/quickstart-traefik)
- [Installation](/docs/installation)
- [Authentication](/docs/authentication)
- [DNS Providers](/dns-providers)
