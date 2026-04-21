# 🛡️ Home SOC Lab

A personal Security Operations Center (SOC) and cloud infrastructure lab running on a physical Ubuntu Server 24.04 LTS machine. Built as a portfolio demonstrating blue team detection, log monitoring, threat correlation, and self-hosted cloud infrastructure skills.

---

## 📐 Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                  Home SOC Lab Server                    │
│              Ubuntu Server 24.04 LTS                    │
│         Asus TUF A15  |  16GB RAM  |  1TB+ SSD         │
│                  LAN: 192.168.2.15                      │
│                Tailscale: 100.85.43.39                  │
│                                                         │
│  ┌──────────────┐  ┌─────────────┐  ┌───────────────┐  │
│  │ Splunk Free  │  │  Suricata   │  │  Flask SOC    │  │
│  │ SIEM  :8000  │  │  IDS/NSM    │  │  Dashboard    │  │
│  │ REST  :8089  │  │  wlp3s0     │  │  :5000        │  │
│  └──────────────┘  └─────────────┘  └───────────────┘  │
│                                                         │
│  ┌──────────────┐  ┌─────────────┐  ┌───────────────┐  │
│  │  Nextcloud   │  │  Tor +      │  │  UFW          │  │
│  │  Cloud  :80  │  │ Proxychains │  │  Firewall     │  │
│  │  Apache2     │  │  Evasion    │  │               │  │
│  └──────────────┘  └─────────────┘  └───────────────┘  │
└─────────────────────────────────────────────────────────┘
                          │ Tailscale VPN
               ┌──────────────────────┐
               │   Remote Access      │
               │   Windows Client     │
               │   SSH + Browser      │
               └──────────────────────┘
```

---

## 🧰 Stack & Tools

| Component | Tool | Purpose | Port |
|-----------|------|---------|------|
| SIEM | Splunk Free 10.2.1 | Log ingestion, correlation, alerting | 8000 / 8089 |
| Network IDS | Suricata | Packet inspection, ~65K ET rules | — |
| EDR (planned) | Wazuh | Endpoint detection & response | — |
| SOC Dashboard | Flask + psutil | Live service status, log viewer | 5000 |
| Cloud Storage | Nextcloud 33 | Self-hosted file storage | 80 / 443 |
| Evasion Sim | Tor + Proxychains4 | Anonymized traffic, detection testing | — |
| Remote Access | Tailscale | Secure VPN mesh | — |
| Firewall | UFW | Port/access management | — |
| OS | Ubuntu Server 24.04 LTS | Host operating system | — |

---

## 📂 Repository Structure

```
Home_SOC_lab/
├── README.md
├── splunk/
│   ├── queries/          # SPL detection queries
│   ├── configs/          # inputs.conf and other config snippets
│   └── screenshots/      # Splunk dashboard screenshots
├── suricata/
│   ├── rules/            # Custom .rules files
│   └── configs/          # suricata.yaml reference snippets
├── flask-dashboard/
│   ├── app.py
│   ├── templates/
│   ├── static/
│   └── screenshots/
├── tor-proxychains/
│   └── README.md         # Evasion simulation methodology
├── nextcloud/
│   └── README.md
└── docs/
    ├── network-diagram.md
    └── incident-reports/
```

---

## 🚀 Setup & Installation

### Prerequisites

- Ubuntu Server 22.04+ or 24.04 LTS
- 8GB RAM minimum (16GB recommended)
- 100GB+ free disk space

---

### 1. Base System

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget git ufw net-tools
```

---

### 2. Splunk Free

> **Critical:** Always run Splunk as a dedicated `splunk` system user — never root. File ownership conflicts are the most common source of failures.

```bash
# Download Splunk .deb
wget -O /tmp/splunk.deb \
  "https://download.splunk.com/products/splunk/releases/10.2.1/linux/splunk-10.2.1-amd64.deb"
sudo dpkg -i /tmp/splunk.deb

# Set ownership
sudo chown -R splunk:splunk /opt/splunk

# Start and accept license
sudo -u splunk /opt/splunk/bin/splunk start --accept-license

# Enable systemd boot-start (disable init.d first to avoid conflicts)
sudo /opt/splunk/bin/splunk disable boot-start
sudo /opt/splunk/bin/splunk enable boot-start -systemd-managed 1 -user splunk
```

Add log sources to `/opt/splunk/etc/system/local/inputs.conf`:

```ini
[monitor:///var/log/auth.log]
sourcetype = linux_secure
index = main

[monitor:///var/log/suricata/eve.json]
sourcetype = suricata
index = main

[monitor:///var/log/tor/notices.log]
sourcetype = tor
index = main
```

```bash
sudo -u splunk /opt/splunk/bin/splunk restart
# Web UI → http://<server-ip>:8000
```

---

### 3. Suricata

```bash
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt install -y suricata

# Pull ~65,000 Emerging Threats rules
sudo suricata-update
```

Set your interface in `/etc/suricata/suricata.yaml`:

```yaml
af-packet:
  - interface: wlp3s0   # replace with your interface (ip a to check)
```

```bash
sudo systemctl enable --now suricata
sudo systemctl status suricata
```

---

### 4. Flask SOC Dashboard

```bash
sudo apt install -y python3-pip
sudo pip3 install flask psutil --break-system-packages
sudo mkdir /opt/soc-dashboard
# Copy app files from flask-dashboard/ in this repo
```

Create `/etc/systemd/system/homelab-dashboard.service`:

```ini
[Unit]
Description=Home SOC Dashboard
After=network.target

[Service]
User=root
WorkingDirectory=/opt/soc-dashboard
ExecStart=/usr/bin/python3 app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now homelab-dashboard
# Dashboard → http://<server-ip>:5000
```

---

### 5. Nextcloud

```bash
sudo apt install -y apache2 mariadb-server php php-mysql \
  libapache2-mod-php php-xml php-curl php-gd php-zip php-mbstring

wget https://download.nextcloud.com/server/releases/latest.zip
sudo unzip latest.zip -d /var/www/html/
sudo chown -R www-data:www-data /var/www/html/nextcloud
sudo systemctl enable --now apache2
```

---

### 6. Tor + Proxychains4

```bash
sudo apt install -y tor proxychains4
sudo systemctl enable --now tor

# Fix log ownership if broken after any chmod
sudo chown debian-tor:debian-tor /var/log/tor/notices.log
sudo systemctl restart tor
```

---

### 7. Disable Server Sleep

```bash
sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target
```

---

### 8. Firewall (UFW)

```bash
sudo ufw allow 22/tcp     # SSH
sudo ufw allow 80/tcp     # Nextcloud HTTP
sudo ufw allow 443/tcp    # Nextcloud HTTPS
sudo ufw allow 5000/tcp   # Flask SOC Dashboard
sudo ufw allow 8000/tcp   # Splunk Web UI
sudo ufw enable
```

---

## 🔍 Detection Use Cases (MITRE ATT&CK)

| Scenario | Technique | Log Source | SPL Query |
|----------|-----------|------------|-----------|
| SSH brute force | T1110 | auth.log | [queries/](splunk/queries/) |
| Credential stuffing success | T1078 | auth.log | [queries/](splunk/queries/) |
| Tor anonymized traffic | T1090 | tor + suricata | [queries/](splunk/queries/) |
| Suricata high-severity alerts | T1071 | suricata eve.json | [queries/](splunk/queries/) |
| Sudo privilege escalation | T1021 | auth.log | [queries/](splunk/queries/) |

Full SPL query library → [`splunk/queries/`](splunk/queries/)

---

## 🗺️ Roadmap

- [x] Splunk SIEM — live log ingestion (auth, suricata, tor)
- [x] Suricata IDS — Emerging Threats ruleset (~65K rules)
- [x] Flask SOC Dashboard — dark theme, live charts, service controls
- [x] Tor evasion simulation + correlated detection
- [x] Nextcloud self-hosted cloud storage
- [ ] Cowrie SSH honeypot → Splunk pipeline
- [ ] Wazuh EDR integration
- [ ] WireGuard VPN (UDP 51820)
- [ ] Splunk HEC / REST API wired to Flask dashboard
- [ ] Formal incident reports

---

## ⚠️ Disclaimer

This lab is for **educational and portfolio purposes only**. All simulations run in an isolated home network against systems I own and control.

---

*Built by Ron · Ubuntu Server 24.04 LTS · Brampton, ON*
