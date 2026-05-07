# Threat Detection — Suricata IDS + Splunk SIEM

> **Network intrusion detection feeding a SIEM, with SPL queries mapped to MITRE ATT&CK techniques**

---

This is the core SOC component of the lab. Suricata sits on the WiFi interface inspecting every packet against roughly 65,000 Emerging Threats rules and writes structured alerts to `eve.json`. Splunk picks those up alongside `auth.log` and Tor notice logs, and a hand-written SPL library turns that pipeline into something analysts actually use — detection logic that fires on brute force attempts, anonymized traffic, privilege escalation, and credential reuse. Each query maps to a MITRE ATT&CK technique, and each one has been validated against real traffic generated inside the lab.

---

## Architecture

```
Network Traffic (wlp3s0)
        │
        ▼
   Suricata IDS
   ~65K Emerging Threats rules
        │
        ▼
  /var/log/suricata/eve.json
        │
        ▼
   Splunk Free
   index=main
        │
        ▼
  SPL Detection Queries → Alerts
```

---

## MITRE ATT&CK Detections

| Detection | Technique | SPL Query |
|---|---|---|
| SSH brute force (5+ failures) | T1110 | `splunk/queries/ssh_brute_force.spl` |
| Tor anonymized traffic | T1090 | `splunk/queries/tor_traffic.spl` |
| Suricata high-severity alerts | T1071 | `splunk/queries/suricata_alerts.spl` |
| Sudo privilege escalation | T1021 | `splunk/queries/sudo_escalation.spl` |
| Successful login after failures | T1078 | `splunk/queries/credential_stuffing.spl` |

---

## Suricata Setup

```bash
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt install -y suricata
sudo suricata-update   # pulls ~65K Emerging Threats rules
sudo systemctl enable --now suricata
```

Set the monitored interface in `/etc/suricata/suricata.yaml`:

```yaml
af-packet:
  - interface: wlp3s0
```

---

## Splunk Setup

```bash
# Always run as the splunk user — never root
sudo chown -R splunk:splunk /opt/splunk
sudo /opt/splunk/bin/splunk enable boot-start -systemd-managed 1 -user splunk
```

Log sources in `inputs.conf`:

```ini
[monitor:///var/log/auth.log]
sourcetype = linux_secure

[monitor:///var/log/suricata/eve.json]
sourcetype = suricata

[monitor:///var/log/tor/notices.log]
sourcetype = tor
```

Web UI at `http://<server-ip>:8000`.

---

## Ports

| Port | Service |
|---|---|
| 8000 | Splunk Web UI |
| 8089 | Splunk REST API |
| 8088 | Splunk HEC |
