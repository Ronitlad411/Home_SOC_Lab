# Tor + Proxychains4 — Evasion Simulation

## Purpose

Generates anonymized/proxied traffic to test Suricata rules and Splunk detection correlation. Core lab scenario demonstrating T1090 (Proxy) detection.

## Setup

```bash
sudo apt install -y tor proxychains4
sudo systemctl enable --now tor
```

## Traffic Generation

```bash
# Single request through Tor
proxychains4 curl https://check.torproject.org

# Repeated requests for log volume
for i in {1..10}; do proxychains4 curl -s https://example.com > /dev/null; sleep 2; done
```

## Detection in Splunk

Run the Tor Traffic Correlation query from `splunk/queries/` to see correlated alerts across both `suricata` and `tor` sourcetypes.

## MITRE Mapping

| Technique | ID |
|-----------|-----|
| Proxy | T1090 |
| Application Layer Protocol | T1071 |

## Gotcha

If Tor stops logging after any permission change:
```bash
sudo chown debian-tor:debian-tor /var/log/tor/notices.log
sudo systemctl restart tor
```
