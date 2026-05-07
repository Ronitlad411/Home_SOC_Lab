# 🗺️ Architecture

## Network Overview

```
                        Internet
                            │
                       Home Router
                            │
                     ┌──────────────┐
                     │  Ubuntu Server│
                     │  10.0.0.108  │
                     │  Asus TUF A15│
                     │  16GB · 1TB  │
                     └──────┬───────┘
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
   ┌──────┴──────┐  ┌───────┴──────┐  ┌──────┴──────┐
   │  Splunk     │  │  Suricata    │  │  VoltLAB    │
   │  SIEM :8000 │  │  IDS wlp3s0 │  │  Dashboard  │
   │  REST :8089 │  │  eve.json    │  │  :5000      │
   └─────────────┘  └─────────────┘  └─────────────┘
          │                 │
          └────────┬────────┘
                   │ Log Pipeline
          ┌────────┴────────┐
          │  auth.log       │
          │  eve.json       │
          │  tor/notices.log│
          └─────────────────┘

   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
   │  Nextcloud  │  │  Tor +      │  │  WireGuard  │
   │  Cloud :80  │  │ Proxychains │  │  VPN :51820 │
   │  Apache2    │  │  T1090 sim  │  │             │
   └─────────────┘  └─────────────┘  └─────────────┘

                    Tailscale VPN (100.85.43.39)
                    Remote access from anywhere
```

## Log Flow

```
auth.log ──────────────────────────────────┐
suricata/eve.json ──── Splunk inputs.conf ──┤──► Splunk index=main ──► SPL Queries ──► Alerts
tor/notices.log ───────────────────────────┘
```

## Port Registry

| Port | Service |
|---|---|
| 22 | SSH |
| 80 | Nextcloud HTTP |
| 443 | Nextcloud HTTPS |
| 5000 | VoltLAB SOC Dashboard |
| 5001 | Photo Gallery |
| 8000 | Splunk Web UI |
| 8088 | Splunk HEC |
| 8089 | Splunk REST API |
| 9050 | Tor SOCKS5 |
| 51820/udp | WireGuard VPN |
