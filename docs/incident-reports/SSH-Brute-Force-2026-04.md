# Incident Report — SSH Brute Force Attack
**Date:** 2026-04-15  
**Severity:** Medium  
**Status:** Resolved  
**Technique:** MITRE ATT&CK T1110 — Brute Force

---

## Summary

Splunk detected 47 failed SSH login attempts from a single external IP over a 3-minute window. The attack targeted the default `root` account. No successful authentication occurred. Source IP was blocked via UFW.

---

## Timeline

| Time | Event |
|---|---|
| 02:14:03 | First failed SSH attempt from 185.220.101.47 |
| 02:14:09 | Attempts accelerating — 1 per second |
| 02:16:51 | Splunk alert triggered (threshold: 5 failures / 60s) |
| 02:17:10 | Manual investigation started |
| 02:19:00 | IP blocked via UFW |
| 02:19:05 | Attempts ceased |

---

## Detection

**SPL Query that triggered the alert:**
```spl
index=main sourcetype=linux_secure "Failed password"
| rex field=_raw "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| where count > 5
| sort -count
```

**Result:** `185.220.101.47` — 47 failed attempts in 168 seconds.

---

## Investigation

Checked for successful logins from the same IP:
```spl
index=main sourcetype=linux_secure "Accepted password" OR "Accepted publickey"
| search src_ip="185.220.101.47"
```
Result: **0 successful logins.** Attack did not succeed.

Checked if IP appeared in Suricata alerts:
```spl
index=main sourcetype=suricata src_ip="185.220.101.47"
| stats count by alert.signature
```
Result: Suricata flagged the same IP under `ET SCAN` ruleset.

---

## Response

```bash
sudo ufw deny from 185.220.101.47 to any
sudo ufw reload
```

Verified block:
```bash
sudo ufw status | grep 185.220.101.47
```

---

## Lessons Learned

- SSH port 22 exposed on LAN — consider moving to non-standard port or restricting to Tailscale only
- Fail2ban would automate this block — flagged for implementation
- Alert threshold of 5 failures / 60s is appropriate — no false positives observed

---

## Artifacts

- UFW rule added: `deny from 185.220.101.47`
