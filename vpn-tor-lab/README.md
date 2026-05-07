# VPN + Tor Evasion Lab

> **WireGuard for secure remote access, Tor and Proxychains4 as a live detection target**

---

A SOC stack only proves itself against real evasion traffic. This component does both halves of that loop — WireGuard provides encrypted remote access into the lab from outside, and Tor with Proxychains4 generates the kind of anonymized outbound traffic that real attackers use to obscure their origin. That Tor traffic is the point. It's not a privacy tool here, it's a target — Suricata's Emerging Threats rules fire on it, Splunk correlates it with system logs, and the resulting alerts validate that the detection pipeline catches what it's supposed to catch.

---

## WireGuard VPN

Self-hosted VPN server on UDP 51820, with client profiles configured for Android and Windows.

```bash
sudo apt install -y wireguard
sudo wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey
sudo systemctl enable --now wg-quick@wg0
sudo ufw allow 51820/udp
```

Server and client configs live in `wireguard/configs/`.

---

## Tor + Proxychains4

Tor is configured to accept SOCKS5 connections from the LAN on port 9050. Proxychains4 routes outbound requests through it, generating real anonymized traffic that the IDS pipeline observes and alerts on — a working demonstration of T1090 (Proxy) detection.

```
Client → Proxychains4 → Tor SOCKS5 (:9050) → Tor Network → Internet
                              │
                         Suricata detects
                         Splunk correlates
                         T1090 alert fired
```

```bash
sudo apt install -y tor proxychains4
sudo systemctl enable --now tor

# Restore log ownership if it gets stripped
sudo chown debian-tor:debian-tor /var/log/tor/notices.log
sudo systemctl restart tor
```

Verify the proxy chain end-to-end:

```bash
proxychains4 curl https://check.torproject.org
```

---

## MITRE ATT&CK

| Technique | ID | Detection |
|---|---|---|
| Proxy — Tor | T1090.003 | Suricata ET rules + Splunk Tor log correlation |

---

## Ports

| Port | Service |
|---|---|
| 51820/udp | WireGuard VPN |
| 9050 | Tor SOCKS5 proxy |
