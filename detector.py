import time
from collections import defaultdict


class DetectionEngine:
    def __init__(self):
        self._port_t   = defaultdict(list)
        self._icmp_t   = defaultdict(list)
        self._login_t  = defaultdict(list)
        self._syn_t    = defaultdict(list)
        self._pkt_t    = defaultdict(list)

    @staticmethod
    def _clean(lst, window=60):
        now = time.time()
        return [t for t in lst if now - t < window]

    def analyze(self, src, dst, proto, size, port, ttl, flags):
        now = time.time()

        if size > 1500:
            return ('Large Packet', 'Medium',
                    'Inspect payload. Block source IP if malicious.')

        if proto in ('TCP', 'UDP') and port > 0:
            self._port_t[src] = self._clean(self._port_t[src], 60)
            self._port_t[src].append(now)
            if len(self._port_t[src]) > 100:
                self._port_t[src] = []
                return ('Port Scan', 'High',
                        'Block source IP. Enable port scan rules on firewall.')

        if proto == 'ICMP':
            self._icmp_t[src] = self._clean(self._icmp_t[src], 10)
            self._icmp_t[src].append(now)
            if len(self._icmp_t[src]) > 1000:
                self._icmp_t[src] = []
                return ('Ping Flood', 'High', 'Rate-limit ICMP. Block source IP.')

        if proto == 'TCP' and 'S' in str(flags) and 'A' not in str(flags):
            self._syn_t[src] = self._clean(self._syn_t[src], 10)
            self._syn_t[src].append(now)
            if len(self._syn_t[src]) > 500:
                self._syn_t[src] = []
                return ('SYN Flood', 'Critical',
                        'Enable SYN cookies. Block source IP. Notify ISP.')

        if proto == 'TCP' and port in (22, 21, 3389, 5900, 23):
            self._login_t[src] = self._clean(self._login_t[src], 60)
            self._login_t[src].append(now)
            if len(self._login_t[src]) > 50:
                self._login_t[src] = []
                return ('Brute Force', 'Critical',
                        'Lock account. Block IP. Enable 2FA.')

        self._pkt_t[src] = self._clean(self._pkt_t[src], 5)
        self._pkt_t[src].append(now)
        if len(self._pkt_t[src]) > 2000:
            self._pkt_t[src] = []
            return ('DDoS', 'Critical',
                    'Enable DDoS mitigation. Contact ISP.')

        return (None, None, None)
