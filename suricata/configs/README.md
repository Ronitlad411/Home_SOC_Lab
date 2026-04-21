# Suricata Configuration Notes

## Network Interface

Edit `/etc/suricata/suricata.yaml`:

```yaml
af-packet:
  - interface: wlp3s0   # check yours with: ip a
```

## Rule Updates

```bash
# Update Emerging Threats ruleset (~65K rules)
sudo suricata-update
sudo systemctl restart suricata

# Test config before restart
sudo suricata -T -c /etc/suricata/suricata.yaml
```

## Log Output

EVE JSON → `/var/log/suricata/eve.json`

Key alert fields for Splunk SPL:
- `alert.signature` — rule name
- `alert.severity` — 1 (critical) to 4 (info)
- `src_ip`, `dest_ip`, `proto`
