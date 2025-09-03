# Network Monitor

*A cross‑platform network monitoring and threat detection tool by Kurom Softworks LTD.*

---

## Overview
This network monitor is a lightweight Python-based network monitor that works on **Windows** and **Linux** systems. It captures live traffic, analyzes packet patterns, and raises alerts for suspicious activity such as:

- **DDoS-style floods** (SYN, UDP, ICMP, or generic packet bursts)
- **Traffic spikes** relative to baseline bandwidth usage
- **Port scans** across many hosts or ports

It’s designed for security teams, system administrators, and IT consultants who need visibility into network threats in real time.

---

## Features
- ✅ Cross‑platform (Windows, Linux, macOS likely supported)
- ✅ Detects SYN floods, UDP floods, ICMP floods
- ✅ Alerts on abnormal per-source packet or bandwidth spikes
- ✅ Identifies port scans across many ports/hosts
- ✅ Logs to console + file with configurable verbosity
- ✅ Optional **webhook integration** for Slack, Discord, Teams, etc.
- ✅ Configurable thresholds via YAML or CLI flags
- ✅ Works with or without `scapy` (falls back to interface counters)

---

## Requirements
- Python 3.9+
- Install dependencies:
```bash
pip install scapy psutil requests pyyaml
```

> ⚠️ Live packet capture requires **Administrator** (Windows) or **sudo/root** (Linux).

---

## Quick Start

### Linux
```bash
sudo python network.py
```

### Windows (from Admin PowerShell)
```powershell
python network.py
```

### Optional Flags
- `--iface ETH_NAME` → Specify network interface
- `--bpf "tcp or udp or icmp"` → Use a BPF filter to narrow capture
- `--log /path/to/file.log` → Custom log path
- `--webhook https://...` → Send JSON alerts to webhook URL

---

## Example Alerts
```
2025-09-03 21:08:44,671 WARNING [HIGH] TrafficBurst: High rate from 38.68.134.126: 2357 pps, 3156122 B/s
2025-09-03 21:09:12,012 WARNING [CRITICAL] SYN_Flood: SYN rate 1500/s from 45.77.88.90 with SYN:SYN-ACK ratio ~8.2
2025-09-03 21:10:03,442 WARNING [MEDIUM] PortScan: Possible scan from 192.0.2.44: 180 ports across 40 hosts in last 60s
```

---

## Configuration

You can edit defaults inside the script (`CONFIG`) or provide a YAML file with `--config config.yml`.

Key sections:
- **capture** → Interface, BPF filter, packet-per-second cap
- **detection** → Thresholds for floods, spike detection, port scans
- **alerting** → Log path, verbosity, webhook URL, cooldown

Example YAML:
```yaml
capture:
  iface: eth0
  bpf: "tcp or udp or icmp"

detection:
  thresholds_per_src:
    pps: 4000
    bytes_per_sec: 20000000
alerting:
  webhook_url: "https://hooks.slack.com/..."
  cooldown: 60
```

---

## Tuning & Reducing False Positives
- Streaming video or large downloads can generate thousands of PPS.
- Adjust thresholds in `thresholds_per_src` to suit your network.
- Local LAN devices are excluded from **TrafficBurst** alerts by default.
- Port scan & flood alerts still apply to local devices (optional to disable).

---

## License
© 2025 Kurom Softworks LTD — All Rights Reserved.

This tool is provided for educational and professional use by system administrators and cybersecurity professionals. Unauthorized or malicious use is prohibited.

---

## About Kurom Softworks LTD
Kurom Softworks LTD is a **cybersecurity consulting & software engineering company** specializing in:
- Network security solutions
- Threat detection systems
- Custom defensive software
- Security audits & penetration testing

For consulting inquiries or enterprise integrations, contact us at: **contact@kuromsoftworks.ltd**
