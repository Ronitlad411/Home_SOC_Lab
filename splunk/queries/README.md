# Splunk SPL Detection Queries

All queries target `index=main`. Copy directly into Splunk Search & Reporting.

---

## SSH Brute Force Detection
**MITRE T1110 — Brute Force**

```spl
index=main sourcetype=linux_secure "Failed password"
| stats count by src_ip, user
| where count > 5
| sort -count
| rename src_ip as "Attacking IP", user as "Target User", count as "Failed Attempts"
```

---

## Successful Login After Multiple Failures
**MITRE T1078 — Valid Accounts (credential compromise indicator)**

```spl
index=main sourcetype=linux_secure
| eval event_type=if(match(_raw,"Failed password"),"failure","success")
| stats count(eval(event_type="failure")) as failures,
        count(eval(event_type="success")) as successes by src_ip
| where failures > 3 AND successes > 0
| eval risk="HIGH"
| table src_ip, failures, successes, risk
```

---

## Tor Traffic Correlation
**MITRE T1090 — Proxy / T1071 — Application Layer Protocol**

```spl
index=main (sourcetype=suricata OR sourcetype=tor)
| eval source_type=case(
    sourcetype="suricata", "Suricata IDS Alert",
    sourcetype="tor",      "Tor Proxy Log",
    true(),                "Unknown"
  )
| timechart span=5m count by source_type
```

---

## Suricata High-Severity Alerts
**MITRE T1071 — Application Layer Protocol**

```spl
index=main sourcetype=suricata alert.severity<=2
| spath input=_raw
| stats count by alert.signature, src_ip, dest_ip, alert.severity
| sort -count
| rename alert.signature as "Rule", src_ip as "Source", dest_ip as "Destination", alert.severity as "Severity"
```

---

## Sudo Command Audit
**MITRE T1021 — Privilege Escalation**

```spl
index=main sourcetype=linux_secure "sudo"
| rex field=_raw "COMMAND=(?<command>.+)"
| stats count by user, command, host
| sort -count
| table user, command, host, count
```

---

## Top Attacking IPs (Last 24h)

```spl
index=main sourcetype=linux_secure "Failed password" earliest=-24h
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as attempts by src_ip
| sort -attempts
| head 10
| rename src_ip as "IP Address", attempts as "Attack Attempts"
```

---

## Tor Activity Over Time

```spl
index=main sourcetype=tor
| timechart span=1h count
| rename count as "Tor Events"
```

---

## Live Event Feed (Last 15 Minutes)

```spl
index=main earliest=-15m
| table _time, sourcetype, host, _raw
| sort -_time
| head 100
```

---

## Login Success vs Failure Trend

```spl
index=main sourcetype=linux_secure (Accepted OR Failed)
| eval status=if(match(_raw,"Accepted"),"Success","Failure")
| timechart span=1h count by status
```
