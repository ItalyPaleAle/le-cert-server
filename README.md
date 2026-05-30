# le-cert-server

**[📚 Read the docs](https://le-cert-server.italypaleale.me)**

Secure, centralized Let's Encrypt certificate management for multiple servers and distributed systems.

- **Load-balanced applications** that need the same certificate on multiple nodes.  
   When using Traefik, le-cert-server is an alternative to Traefik Enterprise for using Let's Encrypt across multiple instances.
- **Edge servers** that need to fetch certificates dynamically
- **Development teams** that want to simplify certificate management across environments

le-cert-server uses the DNS-01 challenge to prove ownership of a domain and ask Let's Encrypt for a TLS certficate.

## Why le-cert-server

Managing TLS certificates across multiple servers is challenging:

- 🔄 Manual synchronization between nodes leads to errors and downtime
- 🔐 DNS credentials scattered across different machines increase security risks
- ⏰ Certificate renewals require coordination or risk service interruptions
- 🛡️ Security policies are harder to enforce in distributed environments

le-cert-server solves these problems by providing a single and secure source of truth for your Let's Encrypt certificates. Request certificates from any server, and they're automatically obtained, renewed, and ready to use, all while keeping your DNS credentials safe in one place.

Benefits:

- ✅ Automated certificate lifecycle management
- ✅ Support for 100+ DNS providers (Cloudflare, AWS Route53, Azure DNS, NS1, and many more)
- ✅ Centralized, secure credential storage
- ✅ Wildcard certificate support via DNS-01 challenge
- ✅ Built-in caching to avoid rate limits
- ✅ Simple PSK authentication or optional JWT/OIDC for advanced scenarios

## 📘 Docs

The documentation is available at [`https://le-cert-server.italypaleale.me`](https://le-cert-server.italypaleale.me).

- [Quickstart with Traefik](https://le-cert-server.italypaleale.me/docs/quickstart-traefik)
- [Installation](https://le-cert-server.italypaleale.me/docs/installation)
- [Authentication](https://le-cert-server.italypaleale.me/docs/authentication)
- [DNS Providers](https://le-cert-server.italypaleale.me/dns-providers)

## License

MIT License - See LICENSE file for details
