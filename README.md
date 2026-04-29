# 🛡 OPNSense Analyzer

A self-hosted, privacy-first security auditing tool for OPNSense firewall configuration backups.

Upload your `config.xml` — get instant analysis of firewall rules, VPN settings, interfaces, NAT, and an interactive traffic flow map.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **Security Findings** | Scored analysis with Critical / High / Medium / Low / Info findings |
| 🗺 **Traffic Flow Map** | Interactive D3.js network diagram based on your actual rules |
| 📋 **Rule Browser** | Paginated firewall rule viewer with action/log highlighting |
| ↔ **NAT Review** | Port forwarding rules with endpoint visualization |
| 🌐 **Interface Inspector** | All interfaces with IP, type, bogon status |
| 🔐 **VPN Audit** | OpenVPN cipher/digest/TLS-auth checks, IPsec Phase1 analysis |
| ⚙ **System Summary** | Hostname, version, admin account count |
| 🔒 **Privacy First** | All processing in-memory. Nothing written to disk. Secrets redacted. |

---

## 🚀 Quick Install (Debian 13 / any Debian)

```bash
curl -fsSL https://raw.githubusercontent.com/Hipoglos/opnsense-analyzer/main/install.sh | sudo bash
```

Open: **http://localhost:8081**

> **Custom port:** `PORT=9090 curl -fsSL ... | sudo bash`

---

## 🐳 Manual Docker

```bash
git clone https://github.com/Hipoglos/opnsense-analyzer
cd opnsense-analyzer
docker compose up -d --build
```

---

## 🔒 Security Design

This tool is designed specifically to handle **highly sensitive firewall backups** safely:

### What we protect
- **Passwords, PSKs, certificates, API keys** → Redacted with `***REDACTED***` before any analysis result is returned
- **No file writes** → The uploaded XML is processed entirely in RAM and never written to disk
- **No external connections** → The container has no outbound internet access during analysis
- **Read-only filesystem** → Docker container runs with `read_only: true`
- **Non-root execution** → Application runs as a dedicated `appuser`
- **Dropped capabilities** → All Linux capabilities dropped (`cap_drop: ALL`)
- **No privilege escalation** → `no-new-privileges: true`

### What you should do
- **Never expose port 8080 to the internet** — bind to `127.0.0.1` or restrict with a firewall
- Run on a **trusted machine on your LAN only**
- Use HTTPS if exposing beyond localhost (put nginx/Caddy in front)

### Optional: nginx reverse proxy with TLS
```nginx
server {
    listen 443 ssl;
    server_name audit.internal.yourdomain.com;
    ssl_certificate /etc/ssl/certs/your.crt;
    ssl_certificate_key /etc/ssl/private/your.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
    }
}
```

---

## 📊 What Gets Analyzed

### Firewall Rules
- ❌ Any-to-Any ALLOW rules
- ❌ Missing default deny
- ⚠ WAN allow rules with any source
- ⚠ Rules without logging enabled
- ⚠ Rules without descriptions
- ℹ Disabled rules accumulation

### Interfaces
- ❌ Bogon network blocking not enabled on WAN
- ⚠ Anti-spoofing not configured

### VPN (OpenVPN)
- ❌ Weak ciphers (DES, 3DES, RC4, Blowfish)
- ❌ Weak HMAC (MD5, SHA1)
- ⚠ TLS Auth/Crypt not enabled

### VPN (IPsec)
- ❌ Weak Phase1 encryption
- ⚠ Pre-shared key authentication

### DNS (Unbound)
- ⚠ DNSSEC not enabled
- ⚠ DNS rebinding protection disabled
- ℹ Query forwarding configuration

### Authentication
- ❌ Default 'admin' account active
- ⚠ Too many admin accounts

### Logging
- ❌ No remote syslog configured

### NAT
- ⚠ Port forwarding rules exposing all ports

### Architecture
- ℹ Network segmentation recommendations

---

## 🔄 Update

```bash
cd /srv/opnsense-analyzer
git pull
docker compose up -d --build
```

---

## 🛠 Development

```bash
# Backend only (no Docker)
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8080

# Frontend is static HTML — just edit frontend/static/index.html
```

---

## 📁 Project Structure

```
opnsense-analyzer/
├── backend/
│   ├── main.py           # FastAPI app: parsing, analysis, API
│   └── requirements.txt
├── frontend/
│   └── static/
│       └── index.html    # Full SPA dashboard
├── Dockerfile
├── docker-compose.yml
├── install.sh            # Debian one-liner installer
└── README.md
```

---

## ⚖ License

MIT — use freely, contribute back improvements.

---

> **Disclaimer:** This tool provides automated analysis to assist security review. It does not replace a professional firewall audit. Always validate findings against your specific network requirements.
