---
title: "Installation"
nav_title: "Installation"
weight: 20
---

## Using Docker (Recommended)

Use the pre-built Docker image:

```sh
docker pull ghcr.io/italypaleale/le-cert-server:v0
```

## Using Pre-built Binaries

Download the latest release for your platform from [GitHub Releases](https://github.com/ItalyPaleAle/le-cert-server/releases):

```sh
# Example for linux/amd64
wget https://github.com/ItalyPaleAle/le-cert-server/releases/latest/download/le-cert-server-linux-amd64
chmod +x le-cert-server-linux-amd64
sudo mv le-cert-server-linux-amd64 /usr/local/bin/cert-server
```

## Building from Source

If you prefer to build from source:

```bash
git clone https://github.com/ItalyPaleAle/le-cert-server.git
cd le-cert-server
go build -o le-cert-server ./cmd
```

## Request Your First Certificate

```bash
# Request a certificate using your API key
curl -k -X POST https://localhost:8443/api/certificate \
  -H "Authorization: APIKey your-secure-random-key-here" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

That's it! The certificate and private key are returned in JSON format, ready to use.

**Note:** Use `-k` flag to skip certificate verification if using self-signed certificates for testing.

## Production Deployment

### Systemd Service

Create `/etc/systemd/system/le-cert-server.service`:

```ini
[Unit]
Description=le-cert-server
After=network.target

[Service]
Type=simple
User=le-cert-server
Group=le-cert-server
WorkingDirectory=/usr/local/bin/le-cert-server
ExecStart=/usr/local/bin/le-cert-server -config /etc/cert-server/config.yaml
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable --now le-cert-server
sudo systemctl status le-cert-server
```

### Docker

Use the pre-built Docker image from GitHub Container Registry:

```bash
# Pull the latest image
docker pull ghcr.io/italypaleale/le-cert-server:v0

# Run the container
docker run -d \
  --name le-cert-server \
  -p 8443:8443 \
  -v /var/lib/le-cert-server:/var/lib/le-cert-server \
  -v /etc/le-cert-server/config.yaml:/etc/le-cert-server/config.yaml:ro \
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

volumes:
  cert-data:
```

Start with:

```bash
docker-compose up -d
```
