#!/usr/bin/env python3
from __future__ import annotations

import argparse
import collections
import ipaddress
import json
import logging
import os
import platform
import queue
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Optional, Set, Tuple

# Optional deps
try:
    from scapy.all import sniff, TCP, UDP, IP, IPv6, ICMP, Raw
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

try:
    import psutil
except Exception as e:
    print("psutil is required: pip install psutil", file=sys.stderr)
    raise

try:
    import requests
    REQUESTS_AVAILABLE = True
except Exception:
    REQUESTS_AVAILABLE = False

try:
    import yaml
    YAML_AVAILABLE = True
except Exception:
    YAML_AVAILABLE = False


DEFAULT_LOG_PATH = os.path.join(os.path.dirname(__file__), "kuromsoftworks_network.log")

CONFIG: Dict[str, Any] = {
    "capture": {
        # Interface name (None = auto detect default route interface)
        "iface": None,
        # BPF filter (keep broad by default; you can narrow: e.g., "tcp or udp or icmp")
        "bpf": None,
        # Max packets per second to process (None = unlimited)
        "pps_cap": 2000,
    },
    "detection": {
        # Sliding window length (seconds) for short-term stats
        "window_seconds": 60,
        # DDoS-like bursts flagged when any single source exceeds these per-second rates
        "thresholds_per_src": {
            "pps": 800,         # packets/sec from one source
            "syn_rate": 300,    # SYN packets/sec from one source
            "udp_rate": 500,    # UDP packets/sec from one source
            "icmp_rate": 200,   # ICMP packets/sec from one source
            "bytes_per_sec": 2_000_000,  # ~16 Mbps from one source
        },
        # SYN flood heuristic: SYNs far outnumber SYN-ACKs/resets
        "syn_ack_ratio_min": 4.0,
        # Port scan heuristic: many distinct destination ports in short time
        "portscan": {
            "unique_ports": 120,  # ports within window
            "max_dst_ips": 30,    # if scanning many targets too
        },
        # Spike detection on total interface traffic (fallback or extra guard)
        "iface_spike": {
            "check_every": 2,          # seconds
            "baseline_secs": 120,      # moving baseline window
            "stddev_multiplier": 4.0,  # flag when > mean + k*stddev
            "min_rate_bps": 20_000_000 # ignore if below this absolute rate (~160 Mbps)
        },
        # Local network(s) to treat as internal (auto-adds RFC1918). Helps with classifying inbound/outbound.
        "local_cidrs": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"],
    },
    "alerting": {
        "log_path": DEFAULT_LOG_PATH,
        "level": "INFO",   # DEBUG/INFO/WARNING/ERROR
        # Optional webhook (Slack/Discord/Teams/any) – will POST JSON
        "webhook_url": None,
        # Cooldown seconds to avoid spam for identical alerts
        "cooldown": 60,
        # Send a compact JSON blob containing the key metrics
        "include_metrics": True,
    },
}


@dataclass
class Alert:
    kind: str
    severity: str
    message: str
    fingerprint: str
    metrics: Dict[str, Any] = field(default_factory=dict)


class AlertManager:
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.last_sent: Dict[str, float] = {}
        self.cooldown = float(cfg.get("cooldown", 60))
        log_path = cfg.get("log_path", DEFAULT_LOG_PATH)
        level = getattr(logging, cfg.get("level", "INFO").upper(), logging.INFO)
        logging.basicConfig(
            level=level,
            format='%(asctime)s %(levelname)s %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler(log_path, encoding='utf-8')
            ]
        )
        self.webhook_url = cfg.get("webhook_url") if REQUESTS_AVAILABLE else None
        self.include_metrics = bool(cfg.get("include_metrics", True))

    def _should_send(self, fingerprint: str) -> bool:
        now = time.time()
        last = self.last_sent.get(fingerprint, 0)
        if now - last >= self.cooldown:
            self.last_sent[fingerprint] = now
            return True
        return False

    def send(self, alert: Alert) -> None:
        if not self._should_send(alert.fingerprint):
            return
        msg = f"[{alert.severity}] {alert.kind}: {alert.message}"
        logging.warning(msg)
        if self.webhook_url:
            try:
                payload = {
                    "kind": alert.kind,
                    "severity": alert.severity,
                    "message": alert.message,
                    "fingerprint": alert.fingerprint,
                    "hostname": platform.node(),
                    "ts": int(time.time()),
                }
                if self.include_metrics and alert.metrics:
                    payload["metrics"] = alert.metrics
                requests.post(self.webhook_url, json=payload, timeout=5)
            except Exception as e:
                logging.error(f"Webhook post failed: {e}")


class RollingCounter:
    # Time-bucketed counters over a sliding window (seconds).
    def __init__(self, window_seconds: int):
        self.window = window_seconds
        self.q: Deque[Tuple[float, Dict[str, int]]] = collections.deque()
        self.accum: Dict[str, int] = collections.Counter()
        self.lock = threading.Lock()

    def add(self, key_counts: Dict[str, int]) -> None:
        now = time.time()
        with self.lock:
            self.q.append((now, key_counts))
            for k, v in key_counts.items():
                self.accum[k] = self.accum.get(k, 0) + v
            self._trim(now)

    def value(self, key: str) -> int:
        with self.lock:
            self._trim(time.time())
            return self.accum.get(key, 0)

    def snapshot(self) -> Dict[str, int]:
        with self.lock:
            self._trim(time.time())
            return dict(self.accum)

    def _trim(self, now: float) -> None:
        cutoff = now - self.window
        while self.q and self.q[0][0] < cutoff:
            _, d = self.q.popleft()
            for k, v in d.items():
                nv = self.accum.get(k, 0) - v
                if nv <= 0:
                    self.accum.pop(k, None)
                else:
                    self.accum[k] = nv


class TrafficStats:
    # Aggregates live stats in the last N seconds for detection rules.
    def __init__(self, window_seconds: int):
        self.window = window_seconds
        self.packets_per_src = RollingCounter(window_seconds)
        self.bytes_per_src = RollingCounter(window_seconds)
        self.syn_per_src = RollingCounter(window_seconds)
        self.udp_per_src = RollingCounter(window_seconds)
        self.icmp_per_src = RollingCounter(window_seconds)
        self.syn_ack_per_src = RollingCounter(window_seconds)
        self.dst_ports_per_src: Dict[str, RollingCounter] = {}
        self.dst_ips_per_src: Dict[str, RollingCounter] = {}
        self.lock = threading.Lock()

    def note_packet(self, src: str, dst: str, proto: str, size: int, flags: Optional[str]) -> None:
        if not src:
            return
        self.packets_per_src.add({src: 1})
        self.bytes_per_src.add({src: size})
        if proto == 'TCP':
            if flags and 'S' in flags and 'A' not in flags:
                self.syn_per_src.add({src: 1})
            if flags and 'S' in flags and 'A' in flags:
                self.syn_ack_per_src.add({dst: 1})  # count per destination as proxy for responders
        elif proto == 'UDP':
            self.udp_per_src.add({src: 1})
        elif proto == 'ICMP':
            self.icmp_per_src.add({src: 1})

        # track distinct destination ports and ips for port-scan heuristics
        if proto in ("TCP", "UDP"):
            # Store per-src rolling counters of destinations (count each packet as 1 for port/IP)
            if src not in self.dst_ports_per_src:
                self.dst_ports_per_src[src] = RollingCounter(self.window)
            if src not in self.dst_ips_per_src:
                self.dst_ips_per_src[src] = RollingCounter(self.window)
            # Use composite keys so counting distinct is via snapshot keys
            # We'll add 1 per (src,dst_port) and per (src,dst_ip) per packet; during eval we count unique keys
            # To avoid huge memory, we bucket by string keys and let window trimming handle decay.

    def note_dst_port(self, src: str, dst_port: int) -> None:
        if src not in self.dst_ports_per_src:
            self.dst_ports_per_src[src] = RollingCounter(self.window)
        key = f"p:{dst_port}"
        self.dst_ports_per_src[src].add({key: 1})

    def note_dst_ip(self, src: str, dst_ip: str) -> None:
        if src not in self.dst_ips_per_src:
            self.dst_ips_per_src[src] = RollingCounter(self.window)
        key = f"ip:{dst_ip}"
        self.dst_ips_per_src[src].add({key: 1})

class Detector:
    def __init__(self, cfg: Dict[str, Any], alerter: AlertManager):
        self.cfg = cfg
        self.alert = alerter
        self.stats = TrafficStats(cfg["detection"]["window_seconds"])
        self.local_nets = [ipaddress.ip_network(x) for x in cfg["detection"].get("local_cidrs", [])]

    def _is_local(self, ip: str) -> bool:
        try:
            ipobj = ipaddress.ip_address(ip)
            return any(ipobj in net for net in self.local_nets)
        except Exception:
            return False

    def evaluate(self) -> None:
        dcfg = self.cfg["detection"]
        th = dcfg["thresholds_per_src"]
        for src, pps in self.stats.packets_per_src.snapshot().items():
            # Skip burst alerts for local LAN devices
            if self._is_local(src):
                continue

            bytes_s = self.stats.bytes_per_src.value(src)
            syn_s = self.stats.syn_per_src.value(src)
            udp_s = self.stats.udp_per_src.value(src)
            icmp_s = self.stats.icmp_per_src.value(src)

            # DDoS-like single-source saturation
            if pps >= th["pps"] or bytes_s >= th["bytes_per_sec"]:
                self.alert.send(Alert(
                    kind="TrafficBurst",
                    severity="HIGH",
                    message=f"High rate from {src}: {pps} pps, {bytes_s} B/s",
                    fingerprint=f"burst:{src}",
                    metrics={"src": src, "pps": pps, "bytes_per_sec": bytes_s}
                ))

            # SYN flood
            if syn_s >= th["syn_rate"]:
                synack = self.stats.syn_ack_per_src.value(src)
                ratio = float(syn_s) / max(1.0, float(synack))
                if ratio >= dcfg["syn_ack_ratio_min"]:
                    self.alert.send(Alert(
                        kind="SYN_Flood",
                        severity="CRITICAL",
                        message=f"SYN rate {syn_s}/s from {src} with SYN:SYN-ACK ratio ~{ratio:.1f}",
                        fingerprint=f"synf:{src}",
                        metrics={"src": src, "syn_rate": syn_s, "synack_rate": synack, "ratio": ratio}
                    ))

            # UDP flood
            if udp_s >= th["udp_rate"]:
                self.alert.send(Alert(
                    kind="UDP_Flood",
                    severity="HIGH",
                    message=f"UDP rate {udp_s}/s from {src}",
                    fingerprint=f"udpf:{src}",
                    metrics={"src": src, "udp_rate": udp_s}
                ))

            # ICMP flood
            if icmp_s >= th["icmp_rate"]:
                self.alert.send(Alert(
                    kind="ICMP_Flood",
                    severity="MEDIUM",
                    message=f"ICMP echo rate {icmp_s}/s from {src}",
                    fingerprint=f"icmpf:{src}",
                    metrics={"src": src, "icmp_rate": icmp_s}
                ))

            # Port scan heuristic
            ports_counter = self.stats.dst_ports_per_src.get(src)
            ips_counter = self.stats.dst_ips_per_src.get(src)
            if ports_counter:
                unique_ports = len([k for k in ports_counter.snapshot().keys() if k.startswith('p:')])
            else:
                unique_ports = 0
            if ips_counter:
                unique_ips = len([k for k in ips_counter.snapshot().keys() if k.startswith('ip:')])
            else:
                unique_ips = 0

            pcfg = dcfg["portscan"]
            if unique_ports >= pcfg["unique_ports"] or (unique_ports >= pcfg["unique_ports"]//2 and unique_ips >= pcfg["max_dst_ips"]):
                self.alert.send(Alert(
                    kind="PortScan",
                    severity="MEDIUM",
                    message=f"Possible scan from {src}: {unique_ports} ports across {unique_ips} hosts in last {self.stats.window}s",
                    fingerprint=f"pscan:{src}",
                    metrics={"src": src, "unique_ports": unique_ports, "unique_ips": unique_ips}
                ))

    # Packet processing hook
    def on_packet(self, pkt) -> None:
        try:
            size = int(len(pkt))
            src = None
            dst = None
            proto = None
            flags = None
            dport = None

            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
            elif IPv6 in pkt:
                src = pkt[IPv6].src
                dst = pkt[IPv6].dst

            if TCP in pkt:
                proto = 'TCP'
                flags = pkt[TCP].flags.flagrepr() if hasattr(pkt[TCP].flags, 'flagrepr') else str(pkt[TCP].flags)
                dport = int(pkt[TCP].dport)
            elif UDP in pkt:
                proto = 'UDP'
                dport = int(pkt[UDP].dport)
            elif ICMP in pkt:
                proto = 'ICMP'
            else:
                proto = 'OTHER'

            if src:
                self.stats.note_packet(src, dst or "", proto, size, flags)
                if dport is not None:
                    self.stats.note_dst_port(src, dport)
                if dst:
                    self.stats.note_dst_ip(src, dst)
        except Exception as e:
            logging.debug(f"Packet parse error: {e}")


class InterfaceSpikeWatcher(threading.Thread):
    def __init__(self, iface: Optional[str], cfg: Dict[str, Any], alerter: AlertManager):
        super().__init__(daemon=True)
        self.iface = iface
        self.cfg = cfg
        self.alert = alerter
        self._stop_evt = threading.Event()
        self.samples: Deque[Tuple[float, float]] = collections.deque(maxlen=600)
        self.last_bytes = None
        self.last_ts = None

    def stop(self):
        self._stop_evt.set()

    def _iface_bytes(self) -> Optional[int]:
        # Sum all NICs (or a specific one) for rx+tx bytes
        try:
            io = psutil.net_io_counters(pernic=True if self.iface else False)
            if self.iface:
                if self.iface not in io:
                    return None
                c = io[self.iface]
                return int(c.bytes_sent + c.bytes_recv)
            else:
                c = psutil.net_io_counters()
                return int(c.bytes_sent + c.bytes_recv)
        except Exception:
            return None

    def run(self):
        check_every = self.cfg["check_every"]
        baseline_secs = self.cfg["baseline_secs"]
        mult = self.cfg["stddev_multiplier"]
        min_rate = self.cfg["min_rate_bps"]
        while not self._stop_evt.is_set():
            now = time.time()
            total = self._iface_bytes()
            if total is not None:
                if self.last_bytes is not None and self.last_ts is not None:
                    dt = max(0.001, now - self.last_ts)
                    bps = (total - self.last_bytes) / dt
                    self.samples.append((now, bps))
                    # compute baseline
                    window = [v for (t, v) in self.samples if now - t <= baseline_secs]
                    if len(window) >= max(10, baseline_secs // check_every):
                        mean = sum(window) / len(window)
                        var = sum((x - mean) ** 2 for x in window) / len(window)
                        std = var ** 0.5
                        if bps > mean + mult * std and bps >= min_rate:
                            self.alert.send(Alert(
                                kind="InterfaceSpike",
                                severity="INFO",
                                message=f"Traffic spike: ~{int(bps):,} B/s (baseline ~{int(mean):,} ± {int(std):,})",
                                fingerprint="iface_spike",
                                metrics={"bps": int(bps), "baseline_mean": int(mean), "baseline_std": int(std)}
                            ))
                self.last_bytes = total
                self.last_ts = now
            time.sleep(check_every)


def choose_interface(default: Optional[str]) -> Optional[str]:
    if default:
        return default
    # pick interface with most traffic over a short probe
    try:
        io0 = psutil.net_io_counters(pernic=True)
        time.sleep(0.5)
        io1 = psutil.net_io_counters(pernic=True)
        best = None
        best_delta = -1
        for nic in io0:
            if nic not in io1:
                continue
            d = (io1[nic].bytes_recv + io1[nic].bytes_sent) - (io0[nic].bytes_recv + io0[nic].bytes_sent)
            if d > best_delta:
                best_delta = d
                best = nic
        return best
    except Exception:
        return None


def load_config(path: Optional[str]) -> Dict[str, Any]:
    cfg = CONFIG.copy()
    if path:
        if not YAML_AVAILABLE:
            print("pyyaml not installed; cannot read YAML config", file=sys.stderr)
        else:
            with open(path, 'r', encoding='utf-8') as f:
                user = yaml.safe_load(f) or {}
            # shallow merge top-level keys
            for k, v in user.items():
                if isinstance(v, dict) and k in cfg:
                    cfg[k].update(v)
                else:
                    cfg[k] = v
    return cfg


def scapy_sniffer_loop(det: Detector, iface: Optional[str], bpf: Optional[str], pps_cap: Optional[int], stop_evt: threading.Event):
    # Use scapy sniff with prn callback. Apply simple token bucket if pps_cap is set.
    last_ts = time.time()
    tokens = pps_cap or 0
    rate = pps_cap or 0

    def _cb(pkt):
        nonlocal tokens, last_ts
        if stop_evt.is_set():
            return False
        if rate:
            now = time.time()
            tokens += rate * (now - last_ts)
            last_ts = now
            if tokens > rate:
                tokens = rate
            if tokens < 1:
                return  # drop
            tokens -= 1
        det.on_packet(pkt)
    try:
        sniff(prn=_cb, iface=iface, filter=bpf, store=False, stop_filter=lambda p: stop_evt.is_set())
    except PermissionError:
        logging.error("Permission denied for packet capture. Run as Administrator/root.")
    except Exception as e:
        logging.error(f"Sniffer error: {e}")


def fallback_counter_loop(alerter: AlertManager, cfg: Dict[str, Any], stop_evt: threading.Event):
    """If scapy is missing or not privileged, watch interface counters and alert on spikes only."""
    watcher = InterfaceSpikeWatcher(cfg["capture"].get("iface"), cfg["detection"]["iface_spike"], alerter)
    watcher.start()
    try:
        while not stop_evt.is_set():
            time.sleep(0.5)
    finally:
        watcher.stop()


def main():
    ap = argparse.ArgumentParser(description="Cross-platform network monitor & simple threat detector")
    ap.add_argument('--config', help='YAML config file (optional)')
    ap.add_argument('--iface', help='Interface name (overrides config)')
    ap.add_argument('--bpf', help='BPF filter, e.g., "tcp or udp or icmp"')
    ap.add_argument('--log', help='Log file path (overrides config)')
    ap.add_argument('--webhook', help='Webhook URL for JSON alerts')
    ap.add_argument('--foreground', action='store_true', help='Run in foreground (default)')
    args = ap.parse_args()

    cfg = load_config(args.config)
    if args.iface:
        cfg["capture"]["iface"] = args.iface
    if args.bpf:
        cfg["capture"]["bpf"] = args.bpf
    if args.log:
        cfg["alerting"]["log_path"] = args.log
    if args.webhook:
        cfg["alerting"]["webhook_url"] = args.webhook

    alerter = AlertManager(cfg["alerting"]) 

    iface = choose_interface(cfg["capture"].get("iface"))
    if iface:
        logging.info(f"Using interface: {iface}")
    else:
        logging.info("Interface auto-detect failed; capturing on system default (if privileges allow).")

    stop_evt = threading.Event()

    def handle_sig(signum, frame):
        logging.info("Shutting down...")
        stop_evt.set()

    try:
        signal.signal(signal.SIGINT, handle_sig)
        signal.signal(signal.SIGTERM, handle_sig)
    except Exception:
        pass

    if SCAPY_AVAILABLE:
        det = Detector(cfg, alerter)
        # Interface-level spike watcher (runs alongside scapy)
        watcher = InterfaceSpikeWatcher(iface, cfg["detection"]["iface_spike"], alerter)
        watcher.start()

        # Start evaluation loop
        def evaluator():
            while not stop_evt.is_set():
                det.evaluate()
                time.sleep(1.0)
        t_eval = threading.Thread(target=evaluator, daemon=True)
        t_eval.start()

        scapy_sniffer_loop(det, iface, cfg["capture"].get("bpf"), cfg["capture"].get("pps_cap"), stop_evt)
        watcher.stop()
    else:
        logging.warning("Scapy not available; falling back to interface spike monitoring only.")
        fallback_counter_loop(alerter, cfg, stop_evt)


if __name__ == '__main__':
    main()
