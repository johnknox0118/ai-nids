"""
Packet Capture Module — Real Network Scanning
=============================================
MODE 1 (default on cloud/no-root): Simulator
MODE 2 (local with admin/root):    Real Scapy capture

How it works:
- App auto-detects the best network interface on startup
- Captures ALL packets on that interface (same network as the logged-in device)
- Falls back to simulator if Scapy unavailable or no root
"""
import os
import random
import threading
import time
import queue
import socket
from datetime import datetime

import database as db
from detector import DetectionEngine

# ── State ──────────────────────────────────────────────────
_stop_event     = threading.Event()
_capture_thread = None
_buffer         = []
_buffer_lock    = threading.Lock()
_detector       = DetectionEngine()
_db_queue       = queue.Queue(maxsize=5000)
_db_thread      = None
_current_mode   = "Simulator"   # updated when capture starts
_current_iface  = None          # updated when capture starts

# ── DB write queue ─────────────────────────────────────────
def _db_writer():
    while True:
        try:
            item = _db_queue.get(timeout=1)
            if item is None:
                break
            try:
                if   item[0] == 'packet': db.log_packet(*item[1:])
                elif item[0] == 'threat': db.log_threat(*item[1:])
                elif item[0] == 'alert':  db.log_alert(*item[1:])
            except Exception:
                pass
        except queue.Empty:
            continue

def _enq(kind, *args):
    try: _db_queue.put_nowait((kind,) + args)
    except queue.Full: pass


# ── Interface auto-detection ───────────────────────────────
def _best_interface():
    """
    Find the best network interface:
    1. Any interface that has a real IP (not 127.x.x.x)
    2. Prefer Wi-Fi (wlan, en0, Wi-Fi) over ethernet
    3. Fall back to first available
    """
    try:
        from scapy.all import get_if_list, get_if_addr
        ifaces = get_if_list()

        # Get interface → IP mapping
        iface_ips = {}
        for iface in ifaces:
            try:
                ip = get_if_addr(iface)
                if ip and ip != '0.0.0.0' and not ip.startswith('127.'):
                    iface_ips[iface] = ip
            except Exception:
                pass

        if not iface_ips:
            return ifaces[0] if ifaces else None

        # Prefer Wi-Fi interfaces
        wifi_names = ['wlan', 'wlan0', 'wlan1', 'en0', 'en1', 'wi-fi',
                      'wifi', 'wireless', 'atheros', 'intel', 'broadcom']
        for iface, ip in iface_ips.items():
            if any(w in iface.lower() for w in wifi_names):
                print(f"[Capture] Selected Wi-Fi interface: {iface} ({ip})")
                return iface

        # Fall back to first with real IP
        iface, ip = next(iter(iface_ips.items()))
        print(f"[Capture] Selected interface: {iface} ({ip})")
        return iface

    except Exception as e:
        print(f"[Capture] Interface detection failed: {e}")
        return None


def _get_local_ip():
    """Get the machine's local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


# ── REAL Scapy capture ─────────────────────────────────────
def _process_real_packet(pkt):
    """Process a real captured packet from Scapy."""
    if _stop_event.is_set():
        return
    try:
        from scapy.all import IP, TCP, UDP, ICMP, DNS, Raw

        if not pkt.haslayer(IP):
            return  # Only process IP packets

        src   = pkt[IP].src
        dst   = pkt[IP].dst
        size  = len(pkt)
        ttl   = pkt[IP].ttl
        proto = 'OTHER'
        port  = 0
        flags = ''

        if pkt.haslayer(TCP):
            port  = pkt[TCP].dport
            flags = str(pkt[TCP].flags)
            if port == 443 or pkt[TCP].sport == 443:
                proto = 'HTTPS'
            elif port in (80, 8080) or pkt[TCP].sport in (80, 8080):
                proto = 'HTTP'
            else:
                proto = 'TCP'
        elif pkt.haslayer(UDP):
            port = pkt[UDP].dport
            if port == 53 or pkt[UDP].sport == 53:
                proto = 'DNS'
            else:
                proto = 'UDP'
        elif pkt.haslayer(ICMP):
            proto = 'ICMP'

        # Run detection
        attack, severity, rec = _detector.analyze(src, dst, proto, size, port, ttl, flags)
        status = 'threat' if attack else 'normal'

        # Queue DB writes (never blocks capture thread)
        _enq('packet', src, dst, proto, size, port, ttl, flags, status)
        if attack:
            _enq('threat', attack, severity, src, dst, proto, rec)
            _enq('alert', f"{attack} detected from {src}", severity, src)

        # Live buffer
        with _buffer_lock:
            _buffer.append({
                'timestamp':      datetime.now().strftime('%H:%M:%S'),
                'source_ip':      src,
                'destination_ip': dst,
                'protocol':       proto,
                'packet_size':    size,
                'port':           port,
                'status':         status,
                'attack':         attack or '',
            })
            if len(_buffer) > 500:
                _buffer.pop(0)

    except Exception:
        pass


def _scapy_capture(iface):
    """Real packet capture using Scapy on specified interface."""
    global _current_mode, _current_iface
    try:
        from scapy.all import sniff
        _current_mode  = f"Real capture ({iface})"
        _current_iface = iface
        local_ip = _get_local_ip()
        print(f"[Capture] ✓ Real capture started on {iface} (your IP: {local_ip})")
        print(f"[Capture] Scanning ALL traffic on your network interface")
        sniff(
            iface=iface,
            prn=_process_real_packet,
            store=False,
            stop_filter=lambda p: _stop_event.is_set()
        )
    except PermissionError:
        print("[Capture] ✗ Permission denied — need root/admin. Falling back to simulator.")
        _simulate()
    except Exception as e:
        print(f"[Capture] ✗ Scapy error ({e}) — falling back to simulator.")
        _simulate()


# ── SIMULATOR (fallback) ───────────────────────────────────
_SAMPLE_IPS = [f"192.168.1.{i}" for i in range(1, 20)] + \
              ['10.0.0.1','10.0.0.5','172.16.0.1','8.8.8.8','1.1.1.1']
_ATTACK_IPS = ['203.0.113.5','198.51.100.10','192.0.2.99','45.33.32.156']
_PROTOCOLS  = ['TCP','UDP','ICMP','HTTP','HTTPS','DNS']
_PORTS      = [80, 443, 22, 53, 3306, 8080, 21, 3389]
_RECS = {
    'Port Scan':    'Block source IP. Enable port scan rules on firewall.',
    'Ping Flood':   'Rate-limit ICMP. Block source IP.',
    'SYN Flood':    'Enable SYN cookies. Block source IP. Notify ISP.',
    'Brute Force':  'Lock account. Block IP. Enable 2FA.',
    'DDoS':         'Enable DDoS mitigation. Contact ISP.',
    'Large Packet': 'Inspect payload. Block IP if malicious.',
}

def _simulate():
    """Simulated traffic — stops instantly when _stop_event is set."""
    global _current_mode
    _current_mode = "Simulator (demo mode)"
    print("[Capture] Running in simulator mode")
    while not _stop_event.is_set():
        try:
            is_attacker = random.random() < 0.15
            src   = random.choice(_ATTACK_IPS if is_attacker else _SAMPLE_IPS)
            dst   = random.choice(_SAMPLE_IPS)
            proto = random.choice(_PROTOCOLS)
            size  = random.randint(64, 1500)
            port  = random.choice(_PORTS + [random.randint(1024, 65535)])
            ttl   = random.randint(32, 128)
            flags = random.choice(['S','SA','A','F','PA',''])

            attack, severity, rec = _detector.analyze(src, dst, proto, size, port, ttl, flags)
            if is_attacker and not attack and random.random() < 0.3:
                attack   = random.choice(list(_RECS.keys()))
                severity = random.choice(['Medium','High','Critical'])
                rec      = _RECS[attack]

            status = 'threat' if attack else 'normal'
            _enq('packet', src, dst, proto, size, port, ttl, flags, status)
            if attack:
                _enq('threat', attack, severity, src, dst, proto, rec)
                _enq('alert', f"{attack} detected from {src}", severity, src)

            with _buffer_lock:
                _buffer.append({
                    'timestamp': datetime.now().strftime('%H:%M:%S'),
                    'source_ip': src, 'destination_ip': dst,
                    'protocol': proto, 'packet_size': size,
                    'port': port, 'status': status, 'attack': attack or '',
                })
                if len(_buffer) > 500:
                    _buffer.pop(0)
        except Exception:
            pass
        _stop_event.wait(timeout=random.uniform(0.08, 0.35))
    print("[Capture] Simulator stopped.")


# ── Public API ─────────────────────────────────────────────
def start_capture(use_scapy=None):
    """
    Start packet capture.
    use_scapy=True  → real network capture (needs root/admin + libpcap)
    use_scapy=False → simulator (always works, no root needed)
    use_scapy=None  → auto-detect (tries real, falls back to simulator)
    """
    global _capture_thread, _db_thread

    if not _stop_event.is_set() and _capture_thread and _capture_thread.is_alive():
        print("[Capture] Already running.")
        return

    _stop_event.clear()

    # Start DB writer
    if _db_thread is None or not _db_thread.is_alive():
        _db_thread = threading.Thread(target=_db_writer, daemon=True)
        _db_thread.start()

    # Decide capture mode
    if use_scapy is False:
        target = _simulate
    else:
        # Auto-detect or forced real
        try:
            import scapy
            iface = os.environ.get('CAPTURE_INTERFACE') or _best_interface()
            if iface and use_scapy is not False:
                target = lambda: _scapy_capture(iface)
            else:
                target = _simulate
        except ImportError:
            print("[Capture] Scapy not installed — using simulator")
            target = _simulate

    _capture_thread = threading.Thread(target=target, daemon=True)
    _capture_thread.start()


def stop_capture():
    _stop_event.set()
    print("[Capture] Stop signal sent.")


def is_running():
    return (not _stop_event.is_set() and
            _capture_thread is not None and
            _capture_thread.is_alive())


def get_mode():
    return _current_mode


def get_interface():
    return _current_iface


def get_local_ip():
    return _get_local_ip()


def list_interfaces():
    """Return all available network interfaces with their IPs."""
    try:
        from scapy.all import get_if_list, get_if_addr
        result = []
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
                result.append({'name': iface, 'ip': ip or 'N/A'})
            except Exception:
                result.append({'name': iface, 'ip': 'N/A'})
        return result
    except Exception:
        return []


def get_live_packets():
    with _buffer_lock:
        return list(_buffer[-50:])
