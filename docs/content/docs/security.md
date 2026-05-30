---
title: "Security & Best Practices"
nav_title: "Security & Best Practices"
weight: 40
---

le-cert-server is designed with security as a priority:

- **Centralized Credentials**: DNS provider credentials are stored only on the Certificate Server, not on client nodes
- **Flexible Authentication**: Simple PSK for most use cases, or JWT/OIDC for advanced scenarios
- **HTTPS API**: All communication is encrypted with TLS
- **Audit Trail**: All certificate requests and renewals are logged
- **Least Privilege**: Client nodes only need API access, not DNS provider credentials

## Security Checklist

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
