# Network Diagram

## Lab Topology

```
Internet
    │
 ISP Router (192.168.2.1)
    │
    └── LAN: 192.168.2.0/24
              │
              └── Home SOC Server (192.168.2.15)
                    ├── SSH               :22
                    ├── Nextcloud HTTP    :80
                    ├── Nextcloud HTTPS   :443
                    ├── Flask Dashboard   :5000
                    ├── Splunk Web        :8000
                    ├── Splunk REST API   :8089
                    └── Splunk HEC        :8088

Tailscale Mesh VPN
    └── Server IP: 100.85.43.39
              └── Remote Windows Client (SSH + Browser)
```

## Log Flow

```
/var/log/auth.log           ──┐
/var/log/suricata/eve.json  ──┼──► Splunk (index=main) ──► Dashboards / Alerts
/var/log/tor/notices.log    ──┘
```

## Detection Chain

```
Network Traffic (wlp3s0)
        │
        ▼
   Suricata IDS
  (eve.json alerts)
        │
        ▼
   Splunk SIEM  ◄── auth.log, tor logs
  (SPL queries)
        │
        ▼
Flask SOC Dashboard  ◄── psutil service health
        │
        ▼
  Analyst Response
```
