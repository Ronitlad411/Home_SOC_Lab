#!/usr/bin/env python3
"""
VoltLAB SOC Dashboard — app.py
Single-file Flask app: serves the dashboard UI + all backend APIs.
Deploy: copy to /opt/soc-dashboard/app.py and restart homelab-dashboard.service
"""

from flask import Flask, jsonify, request, Response
import subprocess
import psutil
import os
import json
import re
import time
from datetime import datetime
from pathlib import Path

app = Flask(__name__)

# ─── SERVICE DEFINITIONS ──────────────────────────────────────────────────────
# systemd_name: actual unit name from `systemctl list-units`
SERVICES = {
    'splunk':    {'label': 'Splunk SIEM',         'systemd': 'SplunkD',       'url': 'http://localhost:8000', 'desc': 'security event log management'},
    'suricata':  {'label': 'Suricata IDS',         'systemd': 'suricata',      'url': '',                      'desc': 'network intrusion detection'},
    'nextcloud': {'label': 'Apache2 / Nextcloud',  'systemd': 'apache2',       'url': 'http://localhost',      'desc': 'self-hosted cloud storage'},
    'tor':       {'label': 'Tor Proxy',            'systemd': 'tor@default',   'url': '',                      'desc': 'SOCKS5 anonymizing overlay'},
    'flask':     {'label': 'Flask Dashboard',      'systemd': 'homelab-dashboard', 'url': 'http://localhost:5000', 'desc': 'custom SOC web interface'},
    'wazuh':     {'label': 'Wazuh EDR',            'systemd': 'wazuh-manager', 'url': '',                      'desc': 'endpoint detection & response'},
}

LOG_FILES = {
    'auth':      '/var/log/auth.log',
    'suricata':  '/var/log/suricata/eve.json',
    'tor':       '/var/log/tor/notices.log',
    'syslog':    '/var/log/syslog',
}

# ─── HELPERS ──────────────────────────────────────────────────────────────────
def run_cmd(cmd, timeout=5):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
    except Exception:
        return '', 1

def get_service_state(unit_name):
    out, _ = run_cmd(f'systemctl is-active {unit_name} 2>/dev/null')
    if out == 'active':
        return 'running'
    elif out in ('activating', 'reloading', 'deactivating'):
        return 'restarting'
    return 'stopped'

def get_service_uptime(unit_name):
    out, _ = run_cmd(f'systemctl show {unit_name} --property=ActiveEnterTimestamp 2>/dev/null')
    try:
        ts_str = out.replace('ActiveEnterTimestamp=', '').strip()
        if not ts_str or ts_str == 'n/a':
            return '—'
        # parse: "Mon 2026-05-04 03:09:17 UTC"
        for fmt in ['%a %Y-%m-%d %H:%M:%S %Z', '%a %Y-%m-%d %H:%M:%S']:
            try:
                ts = datetime.strptime(ts_str, fmt)
                diff = int(time.time() - ts.timestamp())
                d, rem = divmod(diff, 86400)
                h, rem = divmod(rem, 3600)
                m = rem // 60
                return f'{d}d {h:02d}h {m:02d}m'
            except Exception:
                continue
    except Exception:
        pass
    return 'active'

def get_process_stats(unit_name):
    """Get CPU and memory for a systemd service's main process."""
    out, _ = run_cmd(f'systemctl show {unit_name} --property=MainPID 2>/dev/null')
    try:
        pid = int(out.replace('MainPID=', '').strip())
        if pid > 0:
            proc = psutil.Process(pid)
            cpu = round(proc.cpu_percent(interval=0.1), 1)
            mem_mb = round(proc.memory_info().rss / 1024 / 1024, 1)
            return cpu, mem_mb
    except Exception:
        pass
    return 0.0, 0.0

def get_uptime_string():
    try:
        secs = int(float(open('/proc/uptime').read().split()[0]))
        d, r = divmod(secs, 86400)
        h, r = divmod(r, 3600)
        m = r // 60
        return f'{d}d {h:02d}h {m:02d}m'
    except Exception:
        return '—'

def parse_auth_log(lines=200):
    """Parse /var/log/auth.log into structured events."""
    events = []
    try:
        path = LOG_FILES['auth']
        if not os.path.exists(path):
            return events
        with open(path, 'r', errors='replace') as f:
            raw = f.readlines()[-lines:]
        for line in reversed(raw):
            line = line.strip()
            if not line:
                continue
            sev = 'low'
            if any(x in line for x in ['Failed password', 'Invalid user', 'authentication failure', 'BREAK-IN']):
                sev = 'high'
            elif any(x in line for x in ['sudo:', 'session opened', 'session closed']):
                sev = 'med'
            events.append({'time': line[:15], 'source': 'auth.log', 'severity': sev, 'message': line[16:] if len(line) > 16 else line})
            if len(events) >= 50:
                break
    except Exception:
        pass
    return events

def parse_suricata_log(lines=100):
    """Parse /var/log/suricata/eve.json into structured events."""
    events = []
    try:
        path = LOG_FILES['suricata']
        if not os.path.exists(path):
            return events
        with open(path, 'r', errors='replace') as f:
            raw = f.readlines()[-lines:]
        for line in reversed(raw):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                evt_type = obj.get('event_type', '')
                ts = obj.get('timestamp', '')[:19].replace('T', ' ')
                if evt_type == 'alert':
                    sig = obj.get('alert', {}).get('signature', 'Suricata alert')
                    sev = obj.get('alert', {}).get('severity', 2)
                    sev_str = 'high' if sev == 1 else 'med' if sev == 2 else 'low'
                    src = obj.get('src_ip', '')
                    dst = obj.get('dest_ip', '')
                    events.append({'time': ts, 'source': 'suricata/eve.json', 'severity': sev_str,
                                   'message': f'{sig} {src} → {dst}'})
                elif evt_type == 'dns':
                    q = obj.get('dns', {}).get('rrname', '')
                    events.append({'time': ts, 'source': 'suricata/eve.json', 'severity': 'low',
                                   'message': f'DNS query: {q}'})
                if len(events) >= 50:
                    break
            except Exception:
                continue
    except Exception:
        pass
    return events

def parse_tor_log(lines=100):
    events = []
    try:
        path = LOG_FILES['tor']
        if not os.path.exists(path):
            return events
        with open(path, 'r', errors='replace') as f:
            raw = f.readlines()[-lines:]
        for line in reversed(raw):
            line = line.strip()
            if not line:
                continue
            sev = 'med' if any(x in line for x in ['warn', 'err', 'circuit']) else 'low'
            events.append({'time': line[:19], 'source': 'tor-monitor', 'severity': sev, 'message': line[20:] if len(line) > 20 else line})
            if len(events) >= 30:
                break
    except Exception:
        pass
    return events

# ─── API ROUTES ───────────────────────────────────────────────────────────────

@app.route('/api/stats')
def api_stats():
    """Real system metrics."""
    try:
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        net_before = psutil.net_io_counters()
        time.sleep(0.5)
        net_after = psutil.net_io_counters()
        net_in  = round((net_after.bytes_recv - net_before.bytes_recv) * 8 / 1_000_000, 2)
        net_out = round((net_after.bytes_sent - net_before.bytes_sent) * 8 / 1_000_000, 2)

        return jsonify({
            'cpu_percent':    round(cpu, 1),
            'memory_percent': round(mem.percent, 1),
            'memory_used_gb': round(mem.used / 1e9, 2),
            'memory_total_gb': round(mem.total / 1e9, 2),
            'disk_percent':   round(disk.percent, 1),
            'disk_used_gb':   round(disk.used / 1e9, 1),
            'disk_total_gb':  round(disk.total / 1e9, 1),
            'net_in_mbps':    net_in,
            'net_out_mbps':   net_out,
            'uptime':         get_uptime_string(),
            'timestamp':      datetime.now().strftime('%H:%M:%S'),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/services')
def api_services():
    """Real service states, uptime and resource usage."""
    result = {}
    for svc_id, svc in SERVICES.items():
        unit = svc['systemd']
        state = get_service_state(unit)
        uptime = get_service_uptime(unit) if state == 'running' else '—'
        cpu, mem_mb = get_process_stats(unit) if state == 'running' else (0.0, 0.0)
        result[svc_id] = {
            'label':   svc['label'],
            'desc':    svc['desc'],
            'url':     svc['url'],
            'state':   state,
            'uptime':  uptime,
            'cpu':     cpu,
            'mem_mb':  mem_mb,
        }
    return jsonify(result)


@app.route('/api/service/<svc_id>', methods=['POST'])
def api_service_action(svc_id):
    """Start / stop / restart a service."""
    if svc_id not in SERVICES:
        return jsonify({'error': 'unknown service'}), 404
    data = request.get_json(silent=True) or {}
    action = data.get('action', '')
    if action not in ('start', 'stop', 'restart'):
        return jsonify({'error': 'invalid action'}), 400
    unit = SERVICES[svc_id]['systemd']
    out, rc = run_cmd(f'sudo /usr/bin/systemctl {action} {unit}', timeout=15)
    return jsonify({'ok': rc == 0, 'output': out, 'service': svc_id, 'action': action})


@app.route('/api/logs')
def api_logs():
    """Merged log stream from auth, suricata, tor."""
    source = request.args.get('source', 'all')
    events = []
    if source in ('all', 'auth'):
        events += parse_auth_log()
    if source in ('all', 'suricata'):
        events += parse_suricata_log()
    if source in ('all', 'tor'):
        events += parse_tor_log()
    # sort newest first (best-effort by time string)
    events.sort(key=lambda x: x.get('time', ''), reverse=True)
    return jsonify({'logs': events[:200], 'total': len(events)})


@app.route('/api/metrics')
def api_metrics():
    """Summary counts for stat cards."""
    try:
        # count auth log events
        auth_events = parse_auth_log(500)
        total_events = len(auth_events) + len(parse_suricata_log(200))
        alerts = sum(1 for e in auth_events if e['severity'] == 'high')
        alerts += len([e for e in parse_suricata_log(200) if e['severity'] == 'high'])
        services_data = {}
        online = 0
        for svc_id, svc in SERVICES.items():
            state = get_service_state(svc['systemd'])
            services_data[svc_id] = state
            if state == 'running':
                online += 1
        return jsonify({
            'total_events':  total_events,
            'active_alerts': alerts,
            'services_online': online,
            'services_total':  len(SERVICES),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── DASHBOARD HTML (embedded) ────────────────────────────────────────────────
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VoltLAB — SOC Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@500;600;700&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
:root{
  --bg:#07070f;--bg2:#0b0b18;--bg3:#0f0f20;--bg4:#131328;
  --border:#1a1a30;--border2:#222240;
  --purple:#7c6fe0;--pdim:rgba(124,111,224,0.12);--pglow:rgba(124,111,224,0.25);
  --cyan:#00e5ff;--cdim:rgba(0,229,255,0.08);
  --green:#00ff88;--gdim:rgba(0,255,136,0.08);
  --red:#ff3355;--rdim:rgba(255,51,85,0.1);
  --amber:#ffaa00;--adim:rgba(255,170,0,0.1);
  --t:#d4daf0;--t2:#6e7a9f;--t3:#2e3550;
  --mono:'Share Tech Mono',monospace;--head:'Rajdhani',sans-serif;--sb:170px;
}
html,body{width:100%;height:100%;overflow:hidden;background:var(--bg);color:var(--t);font-family:var(--mono);font-size:11px;}
::-webkit-scrollbar{width:3px;height:3px;}
::-webkit-scrollbar-track{background:var(--bg);}
::-webkit-scrollbar-thumb{background:var(--border2);}
.shell{display:flex;width:100vw;height:100vh;overflow:hidden;}
.sidebar{width:var(--sb);min-width:var(--sb);height:100vh;background:var(--bg2);border-right:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden;}
.sb-brand{padding:14px 14px 12px;border-bottom:1px solid var(--border);flex-shrink:0;}
.sb-title{font-family:var(--head);font-size:16px;font-weight:700;color:var(--cyan);letter-spacing:.08em;}
.sb-nav{padding:10px 8px;display:flex;flex-direction:column;gap:2px;flex-shrink:0;}
.ni{display:flex;align-items:center;gap:9px;padding:8px 10px;border-radius:5px;cursor:pointer;color:var(--t2);border:1px solid transparent;transition:all .15s;font-family:var(--head);font-weight:500;font-size:13px;letter-spacing:.04em;}
.ni:hover{color:var(--t);background:var(--bg3);}
.ni.on{color:var(--purple);background:var(--pdim);border-color:var(--pglow);}
.ni-ico{width:26px;height:26px;display:flex;align-items:center;justify-content:center;border-radius:4px;flex-shrink:0;}
.sb-sys{padding:10px 12px;border-top:1px solid var(--border);flex:1;overflow:hidden;display:flex;flex-direction:column;justify-content:flex-end;}
.sys-h{color:var(--t2);letter-spacing:.1em;margin-bottom:7px;font-size:9px;}
.sr{display:flex;justify-content:space-between;margin-bottom:2px;}
.sl{color:var(--t3);font-size:9px;letter-spacing:.04em;}
.sv{font-size:9px;}
.bw{height:2px;background:var(--border2);border-radius:1px;margin-bottom:5px;}
.bf{height:2px;border-radius:1px;}
.spkr{display:flex;align-items:flex-end;gap:1px;height:12px;margin:1px 0 5px;}
.spk{width:3px;border-radius:1px;opacity:.7;}
.main{flex:1;height:100vh;overflow:hidden;display:flex;flex-direction:column;}
.page{display:none;flex:1;overflow:hidden;padding:10px 12px;flex-direction:column;gap:7px;}
.page.on{display:flex;}
.stat-row{display:grid;grid-template-columns:repeat(3,1fr);gap:7px;flex-shrink:0;}
.sc{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:10px 12px 8px;position:relative;overflow:hidden;display:flex;flex-direction:column;}
.sc::after{content:'';position:absolute;bottom:0;left:20%;right:20%;height:1px;background:var(--purple);opacity:.3;}
.sc-top{display:flex;align-items:center;gap:8px;margin-bottom:5px;flex-shrink:0;}
.sc-ico{width:26px;height:26px;border-radius:4px;display:flex;align-items:center;justify-content:center;flex-shrink:0;}
.sc-lbl{font-size:9px;letter-spacing:.1em;color:var(--t2);}
.sc-val{font-family:var(--head);font-size:26px;font-weight:700;line-height:1;margin-bottom:6px;flex-shrink:0;}
.sc-spark-wrap{position:relative;height:22px;width:100%;flex-shrink:0;}
.sc-spark{position:absolute;inset:0;width:100%!important;height:100%!important;}
.chart-row{display:grid;grid-template-columns:1fr 1fr;gap:7px;flex:1;min-height:0;}
.cc{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:10px 12px;display:flex;flex-direction:column;min-height:0;}
.cc-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;flex-shrink:0;}
.cc-title{font-size:10px;letter-spacing:.07em;color:var(--t2);}
.cc-badge{font-size:9px;color:var(--t3);border:1px solid var(--border2);padding:1px 7px;border-radius:2px;}
.cw{flex:1;min-height:0;position:relative;}
.ev-card{background:var(--bg2);border:1px solid var(--border);border-radius:6px;overflow:hidden;flex-shrink:0;}
.ev-head{display:flex;justify-content:space-between;align-items:center;padding:7px 12px;border-bottom:1px solid var(--border);}
.ev-title{font-size:10px;letter-spacing:.07em;color:var(--t2);}
.ev-link{font-size:9px;color:var(--purple);cursor:pointer;}
.ev-link:hover{text-decoration:underline;}
.ev-table{width:100%;border-collapse:collapse;}
.ev-table th{padding:5px 10px;font-size:9px;letter-spacing:.07em;color:var(--t3);background:var(--bg3);border-bottom:1px solid var(--border);text-align:left;white-space:nowrap;}
.ev-table td{padding:5px 10px;border-bottom:1px solid var(--border);font-size:10px;vertical-align:middle;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:260px;}
.ev-table tr:last-child td{border-bottom:none;}
.ev-table tr:hover td{background:rgba(124,111,224,.04);}
.dot{width:6px;height:6px;border-radius:50%;display:inline-block;margin-right:6px;vertical-align:middle;}
.dr{background:var(--red);box-shadow:0 0 4px var(--red);}
.da{background:var(--amber);box-shadow:0 0 4px var(--amber);}
.dg{background:var(--green);box-shadow:0 0 3px var(--green);}
.logs-bar{display:flex;align-items:center;gap:6px;flex-shrink:0;flex-wrap:nowrap;}
.fb{font-family:var(--mono);font-size:10px;padding:5px 14px;border-radius:3px;border:1px solid var(--border2);background:var(--bg2);color:var(--t2);cursor:pointer;white-space:nowrap;transition:all .15s;}
.fb:hover{color:var(--t);border-color:var(--purple);}
.fb.on{background:var(--pdim);border-color:var(--purple);color:var(--purple);}
.sw{flex:1;position:relative;display:flex;align-items:center;}
.sico{position:absolute;left:8px;opacity:.3;}
.si{width:100%;background:var(--bg2);border:1px solid var(--border2);border-radius:3px;padding:5px 10px 5px 27px;font-family:var(--mono);font-size:10px;color:var(--t);outline:none;}
.si:focus{border-color:var(--purple);}
.si::placeholder{color:var(--t3);}
.ltog{display:flex;align-items:center;gap:6px;font-size:10px;color:var(--t2);cursor:pointer;padding:5px 10px;border:1px solid var(--border2);border-radius:3px;background:var(--bg2);white-space:nowrap;}
.live-d{width:6px;height:6px;border-radius:50%;background:var(--purple);animation:blink 1.4s infinite;}
@keyframes blink{0%,100%{opacity:1;}50%{opacity:.2;}}
.log-card{background:var(--bg2);border:1px solid var(--border);border-radius:6px;overflow:hidden;flex:1;display:flex;flex-direction:column;min-height:0;}
.lt{width:100%;border-collapse:collapse;}
.lt th{padding:6px 12px;font-size:9px;letter-spacing:.07em;color:var(--t2);background:var(--bg3);border-bottom:1px solid var(--border);text-align:left;white-space:nowrap;position:sticky;top:0;z-index:1;}
.lt td{padding:5px 12px;border-bottom:1px solid rgba(26,26,48,.5);font-size:10px;vertical-align:top;}
.lt tr:hover td{background:rgba(124,111,224,.04);}
.log-scroll{flex:1;overflow-y:auto;min-height:0;}
.lft{font-size:9px;color:var(--t3);white-space:nowrap;width:155px;}
.lfs{color:var(--cyan);width:150px;white-space:nowrap;}
.lfm{color:var(--t);}
.log-foot{display:flex;align-items:center;justify-content:space-between;padding:6px 12px;border-top:1px solid var(--border);background:var(--bg3);font-size:9px;color:var(--t3);flex-shrink:0;}
.pgb{display:flex;gap:3px;}
.pb{padding:2px 7px;border:1px solid var(--border2);border-radius:2px;background:transparent;color:var(--t2);font-family:var(--mono);font-size:9px;cursor:pointer;}
.pb:hover,.pb.on{border-color:var(--purple);color:var(--purple);background:var(--pdim);}
.svc-hdr{display:flex;align-items:center;justify-content:space-between;flex-shrink:0;}
.svc-hl{display:flex;align-items:baseline;gap:10px;}
.svc-ht{font-family:var(--head);font-size:17px;font-weight:700;color:var(--t);letter-spacing:.06em;}
.svc-hs{font-size:10px;color:var(--t2);}
.tbar-r{display:flex;align-items:center;gap:10px;}
.togw{display:flex;align-items:center;gap:6px;font-size:10px;color:var(--t2);}
.tog{width:30px;height:16px;background:var(--border2);border-radius:8px;position:relative;cursor:pointer;transition:background .2s;flex-shrink:0;}
.tog.on{background:var(--green);}
.tog::after{content:'';position:absolute;width:12px;height:12px;background:#fff;border-radius:50%;top:2px;left:2px;transition:left .2s;}
.tog.on::after{left:16px;}
.lpill{display:flex;align-items:center;gap:5px;font-size:10px;color:var(--t2);padding:3px 9px;border:1px solid var(--border2);border-radius:10px;}
.sum-row{display:grid;grid-template-columns:repeat(4,1fr);gap:7px;flex-shrink:0;}
.smc{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:10px 12px;display:flex;align-items:center;gap:10px;}
.sm-ico{width:30px;height:30px;border-radius:5px;display:flex;align-items:center;justify-content:center;flex-shrink:0;}
.sm-l{font-size:9px;letter-spacing:.07em;color:var(--t2);margin-bottom:2px;}
.sm-v{font-family:var(--head);font-size:19px;font-weight:700;line-height:1.1;}
.sm-s{font-size:9px;margin-top:1px;}
.svc-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:7px;flex:1;min-height:0;overflow:hidden;}
.svc-card{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:11px 12px 9px;display:flex;flex-direction:column;min-height:0;}
.sc-hd{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:5px;}
.sc-nm{font-family:var(--head);font-size:14px;font-weight:600;color:var(--t);letter-spacing:.03em;}
.sc-bdg{display:flex;align-items:center;gap:4px;font-size:9px;padding:2px 8px;border-radius:2px;font-weight:500;letter-spacing:.03em;white-space:nowrap;}
.b-run{background:rgba(0,255,136,.1);color:var(--green);border:1px solid rgba(0,255,136,.2);}
.b-stp{background:rgba(255,51,85,.1);color:var(--red);border:1px solid rgba(255,51,85,.2);}
.b-rst{background:rgba(255,170,0,.1);color:var(--amber);border:1px solid rgba(255,170,0,.2);}
.sc-up{font-size:9px;color:var(--cyan);margin-bottom:6px;}
.sc-rr{display:flex;justify-content:space-between;font-size:9px;color:var(--t2);margin-bottom:2px;}
.sc-bar{height:2px;background:var(--border);border-radius:1px;margin-bottom:6px;}
.sc-bf{height:2px;border-radius:1px;}
.sc-btns{display:flex;gap:4px;margin-top:auto;}
.sv{font-family:var(--mono);font-size:9px;padding:4px 0;border-radius:2px;cursor:pointer;flex:1;text-align:center;font-weight:500;letter-spacing:.02em;transition:all .12s;border:1px solid;}
.sv-s{border-color:rgba(0,255,136,.35);color:var(--green);background:transparent;}
.sv-s:hover{background:var(--gdim);}
.sv-x{border-color:rgba(255,51,85,.35);color:var(--red);background:transparent;}
.sv-x:hover{background:var(--rdim);}
.sv-r{border-color:rgba(124,111,224,.35);color:var(--purple);background:transparent;}
.sv-r:hover{background:var(--pdim);}
.sv-l{border-color:rgba(0,229,255,.3);color:var(--cyan);background:transparent;}
.sv-l:hover{background:var(--cdim);}
.bot-row{display:grid;grid-template-columns:2fr 1fr;gap:7px;flex-shrink:0;}
.res-card{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:10px 12px;}
.res-t{font-size:9px;letter-spacing:.1em;color:var(--t2);margin-bottom:8px;}
.res-metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;}
.rm-v{font-family:var(--head);font-size:20px;font-weight:700;line-height:1;}
.rm-l{font-size:9px;letter-spacing:.06em;color:var(--t2);margin:2px 0 4px;}
.rm-s{font-size:9px;color:var(--t3);}
.hlth-card{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:10px 12px;display:flex;flex-direction:column;gap:6px;}
.hlth-t{font-size:9px;letter-spacing:.1em;color:var(--t2);}
.hlth-r{display:flex;align-items:center;gap:7px;font-size:11px;}
.hc{margin-left:auto;font-family:var(--head);font-weight:600;font-size:14px;}
.ring-w{display:flex;justify-content:center;align-items:center;position:relative;height:70px;margin-top:auto;}
.ring-lbl{position:absolute;text-align:center;}
.ring-big{font-family:var(--head);font-size:18px;font-weight:700;color:var(--t);display:block;}
.ring-sm{font-size:9px;color:var(--t2);}
.svc-foot{background:var(--bg2);border:1px solid var(--border);border-radius:5px;padding:6px 12px;display:flex;gap:20px;font-size:9px;flex-shrink:0;}
.sfi{display:flex;gap:6px;align-items:center;}
.sfl{color:var(--t3);letter-spacing:.05em;}
.sfv{color:var(--t2);}
.toast{position:fixed;bottom:16px;right:16px;background:var(--bg4);border:1px solid var(--border2);border-radius:4px;padding:7px 12px;font-size:10px;z-index:999;opacity:0;transform:translateY(5px);transition:all .18s;pointer-events:none;}
.toast.show{opacity:1;transform:translateY(0);}
</style>
</head>
<body>
<div class="shell">

<aside class="sidebar">
  <div class="sb-brand"><div class="sb-title">VoltLAB</div></div>
  <nav class="sb-nav">
    <div class="ni on" onclick="goPage('monitor',this)">
      <div class="ni-ico" style="background:rgba(124,111,224,.15)"><svg width="14" height="14" fill="none" stroke="#7c6fe0" stroke-width="1.8" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg></div>Monitor
    </div>
    <div class="ni" onclick="goPage('logs',this)">
      <div class="ni-ico" style="background:rgba(0,229,255,.08)"><svg width="14" height="14" fill="none" stroke="#00e5ff" stroke-width="1.8" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg></div>Logs
    </div>
    <div class="ni" onclick="goPage('services',this)">
      <div class="ni-ico" style="background:rgba(0,255,136,.08)"><svg width="14" height="14" fill="none" stroke="#00ff88" stroke-width="1.8" viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg></div>Services
    </div>
  </nav>
  <div class="sb-sys">
    <div class="sys-h">SYSTEM STATUS</div>
    <div class="sr"><span class="sl">CPU USAGE</span><span class="sv" style="color:var(--green)" id="sb-cpu">—</span></div>
    <div class="bw"><div class="bf" id="sb-cpub" style="width:0%;background:var(--green)"></div></div>
    <div class="sr"><span class="sl">MEMORY USAGE</span><span class="sv" style="color:var(--purple)" id="sb-mem">—</span></div>
    <div class="bw"><div class="bf" id="sb-memb" style="width:0%;background:var(--purple)"></div></div>
    <div class="sr"><span class="sl">DISK USAGE</span><span class="sv" style="color:var(--amber)" id="sb-disk">—</span></div>
    <div class="bw"><div class="bf" id="sb-diskb" style="width:0%;background:var(--amber)"></div></div>
    <div class="sr" style="margin-top:3px"><span class="sl">NETWORK IN</span><span class="sv" style="color:var(--cyan)" id="sb-ni">—</span></div>
    <div class="spkr" id="sp-in"></div>
    <div class="sr"><span class="sl">NETWORK OUT</span><span class="sv" style="color:var(--cyan)" id="sb-no">—</span></div>
    <div class="spkr" id="sp-out"></div>
    <div class="sr" style="margin-top:3px"><span class="sl">UPTIME</span><span class="sv" id="sb-up">—</span></div>
    <div class="sr"><span class="sl">LAST UPDATE</span><span class="sv" style="color:var(--purple)" id="sb-ts">—</span></div>
  </div>
</aside>

<div class="main">

<!-- MONITOR -->
<section class="page on" id="page-monitor">
  <div class="stat-row">
    <div class="sc">
      <div class="sc-top"><div class="sc-ico" style="background:rgba(124,111,224,.12);border:1px solid rgba(124,111,224,.2)"><svg width="13" height="13" fill="none" stroke="#7c6fe0" stroke-width="1.8" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg></div><span class="sc-lbl">TOTAL EVENTS</span></div>
      <div class="sc-val" id="sv-ev">—</div><div class="sc-spark-wrap"><canvas class="sc-spark" id="ssp-ev"></canvas></div>
    </div>
    <div class="sc">
      <div class="sc-top"><div class="sc-ico" style="background:rgba(255,51,85,.1);border:1px solid rgba(255,51,85,.2)"><svg width="13" height="13" fill="none" stroke="#ff3355" stroke-width="1.8" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg></div><span class="sc-lbl">ACTIVE ALERTS</span></div>
      <div class="sc-val" style="color:var(--red)" id="sv-al">—</div><div class="sc-spark-wrap"><canvas class="sc-spark" id="ssp-al"></canvas></div>
    </div>
    <div class="sc">
      <div class="sc-top"><div class="sc-ico" style="background:rgba(0,229,255,.08);border:1px solid rgba(0,229,255,.15)"><svg width="13" height="13" fill="none" stroke="#00e5ff" stroke-width="1.8" viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg></div><span class="sc-lbl">SERVICES ONLINE</span></div>
      <div class="sc-val" style="color:var(--cyan)" id="sv-svc">—</div><div class="sc-spark-wrap"><canvas class="sc-spark" id="ssp-svc"></canvas></div>
    </div>
  </div>
  <div class="chart-row">
    <div class="cc">
      <div class="cc-head"><span class="cc-title">NETWORK TRAFFIC (LIVE)</span><span class="cc-badge">LAST 60 MIN</span></div>
      <div class="cw"><canvas id="ct-tr"></canvas></div>
    </div>
    <div class="cc">
      <div class="cc-head"><span class="cc-title">EVENT FREQUENCY (LIVE)</span><span class="cc-badge">LAST 60 MIN</span></div>
      <div class="cw"><canvas id="ct-ev"></canvas></div>
    </div>
  </div>
  <div class="ev-card">
    <div class="ev-head"><span class="ev-title">RECENT EVENTS</span><span class="ev-link" onclick="goPage('logs',document.querySelectorAll('.ni')[1])">VIEW ALL EVENTS &gt;</span></div>
    <table class="ev-table"><thead><tr><th>TIME</th><th>SEVERITY</th><th>SOURCE</th><th>MESSAGE</th></tr></thead>
    <tbody id="ev-tbody"></tbody></table>
  </div>
</section>

<!-- LOGS -->
<section class="page" id="page-logs">
  <div class="logs-bar">
    <button class="fb on" onclick="setF('all',this)">ALL</button>
    <button class="fb" onclick="setF('auth',this)">AUTH</button>
    <button class="fb" onclick="setF('suricata',this)">SURICATA</button>
    <button class="fb" onclick="setF('tor',this)">TOR</button>
    <div class="sw">
      <svg class="sico" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
      <input class="si" id="log-s" placeholder="search logs, IPs, event types..." oninput="renderLogs()">
    </div>
    <div class="ltog" onclick="toggleLive()">
      <div class="live-d" id="lt-d"></div><span id="lt-l">AUTO-REFRESH ON</span>
    </div>
    <div class="togw" style="margin-left:4px">
      <div class="tog on" id="tog-l" onclick="toggleLive()"></div>
    </div>
    <div class="lpill"><div class="live-d"></div>LIVE</div>
  </div>
  <div class="log-card">
    <div class="log-scroll">
      <table class="lt" style="width:100%">
        <thead><tr><th style="width:155px;color:var(--t)">TIME ▾</th><th style="width:160px">SOURCE</th><th>SEVERITY</th><th>MESSAGE</th></tr></thead>
        <tbody id="log-tbody"></tbody>
      </table>
    </div>
    <div class="log-foot">
      <span id="log-cnt">LOADING...</span>
      <div class="pgb"><button class="pb on">1</button><button class="pb">2</button><button class="pb">3</button><button class="pb">›</button></div>
      <span style="color:var(--t3)">LIVE FEED</span>
    </div>
  </div>
</section>

<!-- SERVICES -->
<section class="page" id="page-services">
  <div class="svc-hdr">
    <div class="svc-hl"><span class="svc-ht">SERVICES</span><span class="svc-hs">Service management and control</span></div>
    <div class="tbar-r">
      <div style="display:flex;gap:6px;">
        <button class="sv sv-s" style="padding:4px 12px;flex:none;" onclick="allAct('start')">▶ start_all</button>
        <button class="sv sv-x" style="padding:4px 12px;flex:none;" onclick="allAct('stop')">■ stop_all</button>
        <button class="sv sv-r" style="padding:4px 12px;flex:none;" onclick="allAct('restart')">↺ restart_all</button>
      </div>
      <div class="togw"><div class="tog on"></div><span>AUTO-REFRESH ON</span></div>
      <div class="lpill"><div class="live-d"></div>LIVE</div>
    </div>
  </div>
  <div class="sum-row">
    <div class="smc">
      <div class="sm-ico" style="background:rgba(0,229,255,.08);border:1px solid rgba(0,229,255,.15)"><svg width="15" height="15" fill="none" stroke="#00e5ff" stroke-width="1.8" viewBox="0 0 24 24"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg></div>
      <div><div class="sm-l">SERVICES ONLINE</div><div class="sm-v" style="color:var(--cyan)" id="sum-on">—</div><div class="sm-s" style="color:var(--t2)" id="sum-pct">—</div></div>
    </div>
    <div class="smc">
      <div class="sm-ico" style="background:rgba(124,111,224,.1);border:1px solid rgba(124,111,224,.2)"><svg width="15" height="15" fill="none" stroke="#7c6fe0" stroke-width="1.8" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></div>
      <div><div class="sm-l">TOTAL SERVICES</div><div class="sm-v" style="color:var(--purple)" id="sum-tot">6</div><div class="sm-s" style="color:var(--t2)">Configured</div></div>
    </div>
    <div class="smc">
      <div class="sm-ico" style="background:var(--rdim);border:1px solid rgba(255,51,85,.2)"><svg width="15" height="15" fill="none" stroke="#ff3355" stroke-width="1.8" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg></div>
      <div><div class="sm-l">STOPPED SERVICES</div><div class="sm-v" style="color:var(--red)" id="sum-stp">—</div><div class="sm-s" style="color:var(--red)">Require attention</div></div>
    </div>
    <div class="smc">
      <div class="sm-ico" style="background:rgba(255,170,0,.08);border:1px solid rgba(255,170,0,.2)"><svg width="15" height="15" fill="none" stroke="#ffaa00" stroke-width="1.8" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></div>
      <div><div class="sm-l">LAST REFRESH</div><div class="sm-v" style="color:var(--amber);font-size:15px;" id="sum-ts">—</div><div class="sm-s" style="color:var(--t2)" id="sum-dt">May 04, 2026</div></div>
    </div>
  </div>
  <div class="svc-grid" id="svc-grid"></div>
  <div class="bot-row">
    <div class="res-card">
      <div class="res-t">SYSTEM RESOURCES</div>
      <div class="res-metrics">
        <div><div class="rm-v" style="color:var(--green)" id="r-cpu">—</div><div class="rm-l">CPU LOAD</div><div style="position:relative;height:22px;width:100%"><canvas id="rsp-cpu" style="position:absolute;inset:0;width:100%!important;height:100%!important"></canvas></div><div class="rm-s" id="r-cpu-s">—</div></div>
        <div><div class="rm-v" style="color:var(--purple)" id="r-mem">—</div><div class="rm-l">MEMORY USAGE</div><div style="position:relative;height:22px;width:100%"><canvas id="rsp-mem" style="position:absolute;inset:0;width:100%!important;height:100%!important"></canvas></div><div class="rm-s" id="r-mem-s">—</div></div>
        <div><div class="rm-v" style="color:var(--amber)" id="r-disk">—</div><div class="rm-l">DISK USAGE</div><div style="position:relative;height:22px;width:100%"><canvas id="rsp-disk" style="position:absolute;inset:0;width:100%!important;height:100%!important"></canvas></div><div class="rm-s" id="r-disk-s">—</div></div>
        <div><div class="rm-v" style="color:var(--cyan);font-size:15px;" id="r-net">—</div><div class="rm-l">NETWORK (IN/OUT)</div><div style="position:relative;height:22px;width:100%"><canvas id="rsp-net" style="position:absolute;inset:0;width:100%!important;height:100%!important"></canvas></div><div class="rm-s">Mbps</div></div>
      </div>
    </div>
    <div class="hlth-card">
      <div class="hlth-t">SERVICE HEALTH</div>
      <div class="hlth-r"><span class="dot dg"></span><span style="color:var(--t2)">Healthy</span><span class="hc" style="color:var(--green)" id="h-ok">—</span></div>
      <div class="hlth-r"><span class="dot dr"></span><span style="color:var(--t2)">Stopped</span><span class="hc" style="color:var(--red)" id="h-stp">—</span></div>
      <div class="hlth-r"><span class="dot da"></span><span style="color:var(--t2)">Degraded</span><span class="hc" style="color:var(--amber)">0</span></div>
      <div class="ring-w"><canvas id="h-ring" width="70" height="70"></canvas><div class="ring-lbl"><span class="ring-big" id="ring-v">—</span><span class="ring-sm" id="ring-pct">—</span></div></div>
    </div>
  </div>
  <div class="svc-foot">
    <div class="sfi"><span class="sfl">HOST:</span><span class="sfv">soc-lab-01</span></div>
    <div class="sfi"><span class="sfl">OS:</span><span class="sfv">Ubuntu 24.04 LTS</span></div>
    <div class="sfi"><span class="sfl">KERNEL:</span><span class="sfv">6.8.0-generic</span></div>
    <div class="sfi"><span class="sfl">ARCH:</span><span class="sfv">x86_64</span></div>
    <div class="sfi"><span class="sfl">INTERFACE:</span><span class="sfv">wlp3s0</span></div>
    <div class="sfi"><span class="sfl">TIME:</span><span class="sfv" id="f-time">—</span></div>
  </div>
</section>
</div>
</div>
<div class="toast" id="toast"></div>

<script>
// ── UTILS ──────────────────────────────────────────────────
function rnd(a,b){return Math.floor(Math.random()*(b-a+1))+a;}
function rndA(n,a,b){return Array.from({length:n},()=>rnd(a,b));}
function tLbls(n){const now=new Date(),l=[];for(let i=n-1;i>=0;i--){const d=new Date(now-i*60000);l.push(d.getHours().toString().padStart(2,'0')+':'+d.getMinutes().toString().padStart(2,'0'));}return l;}
function nowTs(){const n=new Date();return n.getHours().toString().padStart(2,'0')+':'+n.getMinutes().toString().padStart(2,'0')+':'+n.getSeconds().toString().padStart(2,'0');}

Chart.defaults.font.family="'Share Tech Mono',monospace";
Chart.defaults.font.size=9;
Chart.defaults.color='#2e3550';
const LO={responsive:true,maintainAspectRatio:false,animation:{duration:300},plugins:{legend:{display:true,position:'right',labels:{boxWidth:6,padding:8,color:'#6e7a9f',font:{size:9}}},tooltip:{backgroundColor:'#0f0f20',borderColor:'#1a1a30',borderWidth:1,padding:7}},scales:{x:{grid:{color:'rgba(26,26,48,.9)'},ticks:{color:'#2e3550',maxTicksLimit:5}},y:{grid:{color:'rgba(26,26,48,.9)'},ticks:{color:'#2e3550'}}}};

// ── MAIN CHARTS ──────────────────────────────────────────
const cTr=new Chart(document.getElementById('ct-tr'),{type:'line',data:{labels:tLbls(60),datasets:[
  {label:'INBOUND',data:rndA(60,200,950),borderColor:'#7c6fe0',backgroundColor:'rgba(124,111,224,.05)',borderWidth:1.5,pointRadius:0,tension:.4},
  {label:'OUTBOUND',data:rndA(60,80,380),borderColor:'#00e5ff',backgroundColor:'rgba(0,229,255,.04)',borderWidth:1.5,pointRadius:0,tension:.4}
]},options:{...LO}});

const cEv=new Chart(document.getElementById('ct-ev'),{type:'line',data:{labels:tLbls(60),datasets:[
  {label:'High',data:rndA(60,5,65),borderColor:'#ff3355',borderWidth:1.5,pointRadius:0,tension:.4,fill:false},
  {label:'Med',data:rndA(60,20,130),borderColor:'#ffaa00',borderWidth:1.5,pointRadius:0,tension:.4,fill:false},
  {label:'Low',data:rndA(60,10,80),borderColor:'#00ff88',borderWidth:1.5,pointRadius:0,tension:.4,fill:false}
]},options:{...LO}});

setInterval(()=>{
  [cTr,cEv].forEach(c=>{
    c.data.labels.shift();c.data.labels.push(new Date().toTimeString().slice(0,5));
    c.data.datasets.forEach(d=>{d.data.shift();d.data.push(rnd(10,900));});
    c.update('none');
  });
},5000);

// ── MINI SPARKS ──────────────────────────────────────────
function mkSp(id,col){
  const cv=document.getElementById(id);
  cv.style.display='block';cv.style.width='100%';cv.style.height='100%';
  return new Chart(cv,{type:'line',data:{labels:tLbls(20),datasets:[{data:rndA(20,10,100),borderColor:col,borderWidth:1.2,pointRadius:0,tension:.4,fill:false}]},options:{responsive:true,maintainAspectRatio:false,animation:false,plugins:{legend:{display:false},tooltip:{enabled:false}},scales:{x:{display:false},y:{display:false}}}});
}
const spEv=mkSp('ssp-ev','#7c6fe0');
const spAl=mkSp('ssp-al','#ff3355');
const spSv=mkSp('ssp-svc','#00e5ff');
mkSp('rsp-cpu','#00ff88');mkSp('rsp-mem','#7c6fe0');mkSp('rsp-disk','#ffaa00');mkSp('rsp-net','#00e5ff');

function pushSpark(chart,val){
  chart.data.labels.shift();chart.data.labels.push(nowTs());
  chart.data.datasets[0].data.shift();chart.data.datasets[0].data.push(val);
  chart.update('none');
}

// ── FETCH METRICS ────────────────────────────────────────
async function fetchMetrics(){
  try{
    const r=await fetch('/api/metrics');if(!r.ok)return;
    const d=await r.json();
    document.getElementById('sv-ev').textContent=d.total_events?.toLocaleString()??'—';
    document.getElementById('sv-al').textContent=d.active_alerts??'—';
    document.getElementById('sv-svc').textContent=(d.services_online??'—')+' / '+(d.services_total??'—');
    pushSpark(spEv, d.total_events??0);
    pushSpark(spAl, d.active_alerts??0);
    pushSpark(spSv, d.services_online??0);
  }catch(e){}
}
fetchMetrics();setInterval(fetchMetrics,10000);

// ── FETCH STATS ──────────────────────────────────────────
async function fetchStats(){
  try{
    const r=await fetch('/api/stats');if(!r.ok)return;
    const d=await r.json();
    const c=d.cpu_percent,m=d.memory_percent,dk=d.disk_percent;
    document.getElementById('sb-cpu').textContent=c+'%';document.getElementById('sb-cpub').style.width=c+'%';
    document.getElementById('sb-mem').textContent=m+'%';document.getElementById('sb-memb').style.width=m+'%';
    document.getElementById('sb-disk').textContent=dk+'%';document.getElementById('sb-diskb').style.width=dk+'%';
    document.getElementById('sb-ni').textContent=d.net_in_mbps.toFixed(1)+' Mbps';
    document.getElementById('sb-no').textContent=d.net_out_mbps.toFixed(1)+' Mbps';
    document.getElementById('sb-up').textContent=d.uptime;
    document.getElementById('sb-ts').textContent=d.timestamp;
    document.getElementById('r-cpu').textContent=c+'%';
    document.getElementById('r-mem').textContent=m+'%';
    document.getElementById('r-disk').textContent=dk+'%';
    document.getElementById('r-net').textContent=d.net_in_mbps.toFixed(0)+'/'+d.net_out_mbps.toFixed(0);
    document.getElementById('r-cpu-s').textContent=d.memory_used_gb+' / '+d.memory_total_gb+' GB';
    document.getElementById('r-mem-s').textContent=d.memory_used_gb+' / '+d.memory_total_gb+' GB';
    document.getElementById('r-disk-s').textContent=d.disk_used_gb+' / '+d.disk_total_gb+' GB';
    document.getElementById('sum-ts').textContent=d.timestamp;
    document.getElementById('f-time').textContent=d.timestamp+' UTC';
    buildSparks(c,m);
  }catch(e){}
}
fetchStats();setInterval(fetchStats,5000);

function buildSparks(cpu,mem){
  ['sp-in','sp-out'].forEach((id,i)=>{
    const el=document.getElementById(id);el.innerHTML='';
    const col=i===0?'#7c6fe0':'#00e5ff';
    for(let j=0;j<28;j++){const b=document.createElement('div');b.className='spk';b.style.height=rnd(2,12)+'px';b.style.background=col;el.appendChild(b);}
  });
}
buildSparks(0,0);

// ── LOGS ─────────────────────────────────────────────────
let allLogs=[],curF='all',liveOn=true,liveT;

async function fetchLogs(){
  try{
    const src=curF==='all'?'all':curF;
    const r=await fetch('/api/logs?source='+src);if(!r.ok)return;
    const d=await r.json();
    allLogs=d.logs||[];
    renderLogs();
  }catch(e){}
}
fetchLogs();

function renderLogs(){
  const q=document.getElementById('log-s').value.toLowerCase();
  const tb=document.getElementById('log-tbody');tb.innerHTML='';
  const rows=allLogs.filter(l=>{
    if(curF==='auth'&&!l.source?.includes('auth'))return false;
    if(curF==='suricata'&&!l.source?.includes('suricata'))return false;
    if(curF==='tor'&&!l.source?.includes('tor'))return false;
    if(q&&!l.message?.toLowerCase().includes(q)&&!l.source?.toLowerCase().includes(q))return false;
    return true;
  });
  rows.forEach(l=>{
    const sc=l.severity==='high'?'color:var(--red)':l.severity==='med'?'color:var(--amber)':'color:var(--green)';
    const tr=document.createElement('tr');
    tr.innerHTML=`<td class="lft">${l.time||''}</td><td class="lfs">${l.source||''}</td><td style="${sc};font-size:9px">${(l.severity||'').toUpperCase()}</td><td class="lfm">${l.message||''}</td>`;
    tb.appendChild(tr);
  });
  document.getElementById('log-cnt').textContent=`SHOWING ${rows.length} OF ${allLogs.length} ENTRIES`;
}

function setF(f,btn){curF=f;document.querySelectorAll('.fb').forEach(b=>b.classList.remove('on'));btn.classList.add('on');fetchLogs();}

function toggleLive(){
  liveOn=!liveOn;
  const d=document.getElementById('lt-d'),l=document.getElementById('lt-l'),tg=document.getElementById('tog-l');
  if(liveOn){d.style.background='var(--purple)';d.style.animation='blink 1.4s infinite';l.textContent='AUTO-REFRESH ON';tg.classList.add('on');clearInterval(liveT);liveT=setInterval(fetchLogs,8000);}
  else{d.style.background='var(--t3)';d.style.animation='none';l.textContent='AUTO-REFRESH OFF';tg.classList.remove('on');clearInterval(liveT);}
}
liveT=setInterval(fetchLogs,8000);

// ── SERVICES ─────────────────────────────────────────────
let svcCache={};

async function fetchServices(){
  try{
    const r=await fetch('/api/services');if(!r.ok)return;
    const d=await r.json();
    svcCache=d;
    buildGrid(d);
    updateRecentEvents();
  }catch(e){}
}
fetchServices();setInterval(fetchServices,10000);

function buildGrid(data){
  const g=document.getElementById('svc-grid');g.innerHTML='';
  let running=0,total=0;
  Object.entries(data).forEach(([id,s])=>{
    total++;
    const run=s.state==='running',rst=s.state==='restarting';
    if(run)running++;
    const bc=rst?'b-rst':run?'b-run':'b-stp';
    const bt=rst?'RESTARTING':run?'RUNNING':'STOPPED';
    const bd=rst?'da':run?'dg':'dr';
    const cpuPct=run?Math.min(s.cpu||0,100):0;
    const memMb=run?Math.round(s.mem_mb||0):0;
    const cc=cpuPct>70?'var(--red)':cpuPct>40?'var(--amber)':'var(--purple)';
    const hasUrl=s.url&&s.url.length>0;
    const lb=hasUrl?`<button class="sv sv-l" onclick="window.location.href='${s.url}'">⊕ LAUNCH</button>`:'';
    const extIcon=hasUrl?`<div style="width:18px;height:18px;border:1px solid rgba(0,229,255,.3);border-radius:3px;display:flex;align-items:center;justify-content:center;cursor:pointer;color:var(--cyan)" onclick="window.location.href='${s.url}'" title="Open ${s.label}"><svg width="8" height="8" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg></div>`:'';
    const div=document.createElement('div');
    div.className='svc-card';div.id='sc-'+id;
    div.innerHTML=`
      <div class="sc-hd">
        <span class="sc-nm">${s.label}</span>
        <div style="display:flex;align-items:center;gap:4px">${extIcon}<div class="sc-bdg ${bc}"><div class="dot ${bd}" style="box-shadow:none;width:5px;height:5px"></div>${bt}</div></div>
      </div>
      <div class="sc-up">Uptime: ${s.uptime||'—'}</div>
      <div class="sc-rr"><span>CPU Usage</span><span>${cpuPct.toFixed(1)}%</span></div>
      <div class="sc-bar"><div class="sc-bf" style="width:${cpuPct}%;background:${cc}"></div></div>
      <div class="sc-rr"><span>Memory</span><span>${memMb} MB</span></div>
      <div class="sc-bar"><div class="sc-bf" style="width:${Math.min(memMb/100,100)}%;background:var(--cyan)"></div></div>
      <div class="sc-btns">
        <button class="sv sv-s" onclick="doSvc('${id}','start')">▶ START</button>
        <button class="sv sv-x" onclick="doSvc('${id}','stop')">■ STOP</button>
        <button class="sv sv-r" onclick="doSvc('${id}','restart')">↺ RESTART</button>
        ${lb}
      </div>`;
    g.appendChild(div);
  });
  updateHealth(running,total);
}

function updateHealth(run,tot){
  if(run===undefined){run=Object.values(svcCache).filter(s=>s.state==='running').length;tot=Object.keys(svcCache).length;}
  const pct=tot>0?run/tot:0;
  const pctStr=Math.round(pct*100)+'%';
  document.getElementById('sum-on').textContent=run+' / '+tot;
  document.getElementById('sum-pct').textContent=pctStr+' online';
  document.getElementById('sum-stp').textContent=tot-run;
  document.getElementById('h-ok').textContent=run;
  document.getElementById('h-stp').textContent=tot-run;
  document.getElementById('ring-v').textContent=run+'/'+tot;
  document.getElementById('ring-pct').textContent=pctStr;
  const c=document.getElementById('h-ring'),ctx=c.getContext('2d');
  ctx.clearRect(0,0,70,70);
  ctx.strokeStyle='#1a1a30';ctx.lineWidth=7;ctx.beginPath();ctx.arc(35,35,27,0,Math.PI*2);ctx.stroke();
  ctx.strokeStyle='#00ff88';ctx.lineWidth=7;ctx.lineCap='round';ctx.beginPath();ctx.arc(35,35,27,-Math.PI/2,-Math.PI/2+Math.PI*2*pct);ctx.stroke();
  if(pct<1){ctx.strokeStyle='#ff3355';ctx.beginPath();ctx.arc(35,35,27,-Math.PI/2+Math.PI*2*pct,-Math.PI/2+Math.PI*2);ctx.stroke();}
}

async function doSvc(id,act){
  toast('↺ sending '+act+' to '+id,'warn');
  try{
    const r=await fetch('/api/service/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:act})});
    const d=await r.json();
    if(d.ok){
      const msg={start:'▶ '+id+' started',stop:'■ '+id+' stopped',restart:'↺ '+id+' restarted'};
      toast(msg[act]||act,'ok');
    } else {
      toast('failed: '+id,'err');
    }
  }catch(e){toast('error: '+e.message,'err');}
  setTimeout(fetchServices,1500);
}
window.allAct=function(a){Object.keys(svcCache).forEach(id=>doSvc(id,a));};

// ── RECENT EVENTS from logs ───────────────────────────────
async function updateRecentEvents(){
  try{
    const r=await fetch('/api/logs?source=all');if(!r.ok)return;
    const d=await r.json();
    const tb=document.getElementById('ev-tbody');tb.innerHTML='';
    (d.logs||[]).slice(0,10).forEach(e=>{
      const dc=e.severity==='high'?'dr':e.severity==='med'?'da':'dg';
      const tr=document.createElement('tr');
      tr.innerHTML=`<td style="color:var(--t2);white-space:nowrap"><span class="dot ${dc}"></span>${e.time||''}</td><td style="color:var(--amber);font-size:9px">${(e.severity||'').toUpperCase()}</td><td style="color:var(--cyan)">${e.source||''}</td><td style="color:var(--t2);font-size:10px;max-width:300px;overflow:hidden;text-overflow:ellipsis">${e.message||''}</td>`;
      tb.appendChild(tr);
    });
  }catch(e){}
}
updateRecentEvents();setInterval(updateRecentEvents,10000);

// ── NAV ───────────────────────────────────────────────────
function goPage(n,el){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('on'));
  document.querySelectorAll('.ni').forEach(i=>i.classList.remove('on'));
  document.getElementById('page-'+n).classList.add('on');
  el.classList.add('on');
  if(n==='logs')fetchLogs();
  if(n==='services')fetchServices();
}

// ── TOAST ─────────────────────────────────────────────────
function toast(msg,type='info'){
  const t=document.getElementById('toast');t.textContent=msg;
  const bc={ok:'rgba(0,255,136,.3)',err:'rgba(255,51,85,.3)',warn:'rgba(255,170,0,.3)',info:'rgba(124,111,224,.3)'};
  t.style.borderColor=bc[type]||bc.info;t.classList.add('show');
  clearTimeout(t._t);t._t=setTimeout(()=>t.classList.remove('show'),2500);
}
</script>
</body>
</html>"""


@app.route('/')
def index():
    return Response(DASHBOARD_HTML, mimetype='text/html')


@app.route('/static/<path:filename>')
def static_files(filename):
    return app.send_static_file(filename)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
