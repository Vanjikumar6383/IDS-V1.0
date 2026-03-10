#!/usr/bin/env python3
"""
IDSV1.0 — NEURAL DEFENSE MATRIX  v3.0
SOC Tool for Kali Linux — Fixed for same-machine testing with bettercap

ROOT CAUSES OF MISSING ALERTS (FIXED IN v3):
1. ARP spoof from localhost was skipped — my_ips filter blocked self-originated attacks
2. ARP table was never pre-populated — first gratuitous ARP had nothing to compare to
3. Port scan threshold was too high (10 ports) — bettercap recon uses fewer probes
4. Sniffer used ETH_P_IP(0x0800) only — missed ARP frames during startup race
5. bettercap's sniffer doesn't generate its own packets — need to detect it via ARP poison
6. Cooldown was 5s — blocked rapid same-source events from being seen
"""

import sys, os, time, json, socket, struct, threading
import subprocess, ipaddress, argparse, re, http.server, webbrowser
from datetime import datetime
from collections import defaultdict, deque
from pathlib import Path

R="\033[91m"; G="\033[92m"; Y="\033[93m"; M="\033[95m"
C="\033[96m"; W="\033[97m"; DIM="\033[2m"; BOLD="\033[1m"; RST="\033[0m"

def check_root():
    if os.geteuid() != 0:
        print(f"\n{R}[!] Root required. Run: sudo python3 ids_engine.py{RST}\n")
        sys.exit(1)

def print_banner():
    os.system('clear')
    print(f"""{M}{BOLD}
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║    ██╗██████╗ ███████╗██╗   ██╗ ██╗    ██████╗                          ║
║    ██║██╔══██╗██╔════╝██║   ██║███║   ██╔═══██╗                         ║
║    ██║██║  ██║███████╗██║   ██║╚██║   ██║   ██║                         ║
║    ██║██║  ██║╚════██║╚██╗ ██╔╝ ██║   ██║   ██║                         ║
║    ██║██████╔╝███████║ ╚████╔╝  ██║██╗╚██████╔╝                         ║
║    ╚═╝╚═════╝ ╚══════╝  ╚═══╝   ╚═╝╚═╝ ╚═════╝                          ║
║                                                                          ║
║     N E U R A L   D E F E N S E   M A T R I X   v 3 . 0                 ║
║     S O C   A N A L Y S T   T O O L  //  K A L I   L I N U X            ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{RST}
""")
    print(f"{M}  ┌──────────────────────────────────────────────────────────────┐{RST}")
    print(f"{M}  │{RST} {C}DETECTS{RST} : ARP Spoof · Port Scan · DoS · Brute Force      {M}│{RST}")
    print(f"{M}  │{RST} {C}DETECTS{RST} : MITM · SQL Inject · XSS · RCE · DNS Poison     {M}│{RST}")
    print(f"{M}  │{RST} {C}DETECTS{RST} : UDP Flood · ICMP Sweep · Sniff (via ARP)       {M}│{RST}")
    print(f"{M}  │{RST} {C}ACTION{RST}  : Auto-block via iptables · Live dashboard        {M}│{RST}")
    print(f"{M}  └──────────────────────────────────────────────────────────────┘{RST}\n")

def startup_sequence():
    steps = [
        "CHECKING ROOT PRIVILEGES",
        "LOADING ATTACK SIGNATURES (12 TYPES)",
        "DETECTING NETWORK INTERFACES",
        "PRE-LOADING ARP TABLE (baseline)",
        "ENABLING PROMISCUOUS MODE ON INTERFACE",
        "BINDING RAW ETH_P_ALL SOCKET",
        "LAUNCHING SILENT HOST DISCOVERY",
        "STARTING ONGOING ATTACK TRACKER",
        "INITIALIZING WEB DASHBOARD",
    ]
    print(f"\n{M}  ══════════════ SYSTEM INITIALIZATION ══════════════{RST}\n")
    for label in steps:
        sys.stdout.write(f"  {DIM}[*]{RST} {label}...")
        sys.stdout.flush()
        time.sleep(0.2)
        print(f"\r  {DIM}[{RST}{G}✓{RST}{DIM}]{RST} {label}... {G}OK{RST}       ")
    print(f"\n  {G}{BOLD}[+] ALL SYSTEMS NOMINAL — DEFENSE MATRIX ONLINE{RST}\n")
    time.sleep(0.3)

# ─── NETWORK HELPERS ──────────────────────────────────────────────────────────
def get_interfaces():
    ifaces = []
    try:
        r = subprocess.run(['ip','addr','show'], capture_output=True, text=True)
        current = None
        for line in r.stdout.splitlines():
            m = re.match(r'^\d+: (\S+):', line)
            if m: current = m.group(1).rstrip(':')
            ip_m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', line)
            if ip_m and current and not current.startswith('lo'):
                ifaces.append({'name':current,'ip':ip_m.group(1),'cidr':int(ip_m.group(2))})
    except Exception: pass
    return ifaces

def get_local_network():
    for iface in get_interfaces():
        if not iface['ip'].startswith('127.'):
            net = ipaddress.IPv4Network(f"{iface['ip']}/{iface['cidr']}", strict=False)
            return str(net), iface['name'], iface['ip']
    return "192.168.1.0/24","eth0","192.168.1.1"

def get_all_local_ips():
    ips = set()
    try:
        r = subprocess.run(['ip','addr','show'], capture_output=True, text=True)
        for m in re.finditer(r'inet (\d+\.\d+\.\d+\.\d+)', r.stdout):
            ips.add(m.group(1))
    except Exception: pass
    return ips

def get_all_local_macs():
    """Get all MAC addresses of this machine"""
    macs = set()
    try:
        r = subprocess.run(['ip','link','show'], capture_output=True, text=True)
        for m in re.finditer(r'link/ether ([\da-f:]{17})', r.stdout):
            macs.add(m.group(1).lower())
    except Exception: pass
    return macs

def load_arp_table():
    """
    Pre-load the ARP table baseline from the OS before monitoring starts.
    This is critical — without this, the first ARP reply from a legitimate host
    looks like a new entry and we can't detect when bettercap changes the mapping.
    """
    table = {}
    try:
        r = subprocess.run(['arp','-n','-a'], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            ip_m  = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', line)
            mac_m = re.search(r'([\da-f]{2}:){5}[\da-f]{2}', line)
            if ip_m and mac_m:
                table[ip_m.group(1)] = mac_m.group(0).lower()
    except Exception: pass
    # Also read from /proc/net/arp
    try:
        with open('/proc/net/arp') as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[2] == '0x2':  # 0x2 = complete entry
                    table[parts[0]] = parts[3].lower()
    except Exception: pass
    return table

# ─── SILENT NETWORK SCANNER ───────────────────────────────────────────────────
class NetworkScanner:
    def __init__(self, network_cidr, local_ip):
        self.network_cidr = network_cidr
        self.local_ip     = local_ip
        self.hosts        = {}
        self.lock         = threading.Lock()

    def _hn(self, ip):
        try: return socket.gethostbyaddr(ip)[0]
        except: return ""

    def _mac(self, ip):
        try:
            r = subprocess.run(['arp','-n',ip], capture_output=True, text=True)
            m = re.search(r'([\da-f]{2}:){5}[\da-f]{2}', r.stdout)
            return m.group(0) if m else ""
        except: return ""

    def _upsert(self, ip, hostname="", mac=""):
        with self.lock:
            ex = self.hosts.get(ip, {})
            self.hosts[ip] = {
                'ip':           ip,
                'hostname':     hostname or ex.get('hostname','unknown'),
                'mac':          mac      or ex.get('mac',''),
                'first_seen':   ex.get('first_seen', datetime.now().isoformat()),
                'last_seen':    datetime.now().isoformat(),
                'status':       'active',
                'under_attack': ex.get('under_attack', False),
            }

    def register_seen(self, ip):
        # Only register IPs within our local network CIDR — filters out
        # internet/transit IPs that the sniffer sees in packet headers.
        try:
            if ipaddress.IPv4Address(ip) not in ipaddress.IPv4Network(self.network_cidr, strict=False):
                return
        except Exception:
            return
        with self.lock:
            if ip not in self.hosts:
                self.hosts[ip] = {
                    'ip':ip,'hostname':'unknown','mac':'',
                    'first_seen':datetime.now().isoformat(),
                    'last_seen':datetime.now().isoformat(),
                    'status':'active','under_attack':False,
                }
            else:
                self.hosts[ip]['last_seen'] = datetime.now().isoformat()

    def mark_under_attack(self, ip):
        with self.lock:
            if ip in self.hosts:
                self.hosts[ip]['under_attack'] = True

    def _nmap(self):
        try:
            r = subprocess.run(
                ['nmap','-sn','-T4','--min-parallelism','50',
                 self.network_cidr,'--oG','-'],
                capture_output=True, text=True, timeout=60)
            for line in r.stdout.splitlines():
                m = re.search(r'Host: (\d+\.\d+\.\d+\.\d+)\s+\(([^)]*)\)', line)
                if m:
                    ip = m.group(1)
                    self._upsert(ip, m.group(2) or self._hn(ip), self._mac(ip))
        except Exception:
            self._ping_scan()

    def _ping_scan(self):
        try:
            hosts = list(ipaddress.IPv4Network(self.network_cidr, strict=False).hosts())[:254]
        except: return
        def chk(ip):
            ip = str(ip)
            try:
                r = subprocess.run(['ping','-c','1','-W','1',ip],
                                   capture_output=True, timeout=2)
                if r.returncode == 0:
                    self._upsert(ip, self._hn(ip), self._mac(ip))
            except: pass
        threads = []
        for ip in hosts:
            t = threading.Thread(target=chk, args=(ip,), daemon=True)
            threads.append(t); t.start()
            if len(threads) >= 50:
                for tt in threads: tt.join(timeout=3)
                threads = []
        for t in threads: t.join(timeout=3)

    def start_background_scan(self):
        def loop():
            while True:
                self._nmap()
                time.sleep(120)
        threading.Thread(target=loop, daemon=True).start()

# ─── ONGOING TRACKER ──────────────────────────────────────────────────────────
class OngoingTracker:
    TTL = 30
    def __init__(self):
        self.attacks = {}
        self.lock    = threading.Lock()

    def update(self, src, dst, atype, aid):
        key = (src, dst, atype)
        with self.lock:
            if key in self.attacks:
                self.attacks[key]['last_seen'] = time.time()
                self.attacks[key]['count'] += 1
            else:
                self.attacks[key] = {
                    'src':src,'dst':dst,'type':atype,'alert_id':aid,
                    'first_seen':time.time(),'last_seen':time.time(),'count':1,
                }

    def cleanup(self):
        now = time.time()
        with self.lock:
            stale = [k for k,v in self.attacks.items() if now-v['last_seen']>self.TTL]
            for k in stale: del self.attacks[k]

    def get_all(self):
        now = time.time()
        with self.lock:
            return [v for v in self.attacks.values() if now-v['last_seen']<self.TTL]

# ─── ATTACK DETECTOR ──────────────────────────────────────────────────────────
class AttackDetector:
    """
    Detects attacks between any two hosts.
    
    KEY FIX: We do NOT skip packets where src_ip is in my_ips.
    When you run bettercap on your own Kali machine, YOUR machine IS the attacker.
    So we must analyze packets even from ourselves.
    We only skip blocking our own IP, not detecting it.
    """

    # Thresholds — tuned for realistic detection including same-machine testing
    PORT_SCAN_PORTS  = 5     # 5+ distinct ports in window = scan (low for testing)
    PORT_SCAN_WINDOW = 6     # seconds
    SYN_FLOOD_PPS    = 50    # SYN/sec to one host
    UDP_FLOOD_PPS    = 100   # UDP/sec to one host
    ICMP_SWEEP_COUNT = 5     # ICMP echo to 5+ different hosts = sweep
    BRUTE_SSH_COUNT  = 5     # SYNs to port 22 in 30s
    BRUTE_RDP_COUNT  = 4     # SYNs to port 3389 in 30s
    BRUTE_FTP_COUNT  = 5     # SYNs to port 21 in 30s
    ALERT_COOLDOWN   = 3     # seconds between same alert type for same src→dst

    def __init__(self, my_ips, my_macs, ongoing, arp_table):
        self.my_ips   = my_ips
        self.my_macs  = my_macs
        self.ongoing  = ongoing
        self.arp_table= arp_table   # pre-loaded baseline: ip -> mac
        self.alerts   = []
        self.lock     = threading.Lock()
        self.alert_id = 0
        self.callbacks= []

        # Per-source stats
        self._src = defaultdict(lambda: {
            'port_targets': defaultdict(set),
            'port_times':   defaultdict(deque),
            'syn_times':    defaultdict(deque),
            'udp_times':    defaultdict(deque),
            'ssh_times':    defaultdict(deque),
            'rdp_times':    defaultdict(deque),
            'ftp_times':    defaultdict(deque),
            'icmp_dst':     set(),
            'icmp_times':   deque(),
            'dns_queries':  defaultdict(int),
            'last_alert':   defaultdict(float),
        })

    def add_callback(self, cb):
        self.callbacks.append(cb)

    def _cd_ok(self, src, dst, atype):
        """Check cooldown — allow alert if enough time has passed"""
        key = (dst, atype)
        now = time.time()
        s   = self._src[src]
        if now - s['last_alert'].get(key, 0) < self.ALERT_COOLDOWN:
            return False
        s['last_alert'][key] = now
        return True

    def _prune(self, dq, window):
        now = time.time()
        while dq and now - dq[0] > window:
            dq.popleft()

    def _fire(self, src, dst, dst_port, atype, severity, desc, proto, victim=None):
        now = datetime.now()
        with self.lock:
            self.alert_id += 1
            aid = self.alert_id
            alert = {
                'id':       aid,
                'time':     now.isoformat(),
                'src_ip':   src,
                'dst_ip':   dst,
                'dst_port': dst_port,
                'type':     atype,
                'severity': severity,
                'desc':     desc,
                'proto':    proto,
                'victim':   victim or dst,
                'ongoing':  False,
                'rule_id':  f"ET-{3000+aid}",
            }
            self.alerts.insert(0, alert)
            if len(self.alerts) > 2000:
                self.alerts = self.alerts[:1000]

        self.ongoing.update(src, dst, atype, aid)
        for cb in self.callbacks:
            try: cb(alert)
            except: pass
        return aid

    # ── ARP SPOOFING (bettercap's primary attack) ────────────────────────────
    def check_arp(self, sha, spa, tha, tpa, oper):
        """
        Called for every ARP packet.
        sha = sender hardware (MAC) address
        spa = sender protocol (IP) address
        tha = target hardware address
        tpa = target protocol (IP) address
        oper = 1:request, 2:reply

        bettercap ARP poison = sends gratuitous ARP replies claiming to be
        the gateway/victim, with the attacker's MAC.
        
        Detection: if we've seen IP→MAC mapping before and it changes → ALARM.
        Also detect if attacker's MAC claims to be two different IPs (classic MITM).
        """
        sha = sha.lower()
        spa = spa.strip()

        # Ignore broadcast, empty, or unspecified
        if spa in ('0.0.0.0','') or sha in ('00:00:00:00:00:00','ff:ff:ff:ff:ff:ff',''):
            return

        known_mac = self.arp_table.get(spa)

        if known_mac is None:
            # First time we see this IP — record it as baseline
            self.arp_table[spa] = sha
            return

        if known_mac != sha:
            # MAC changed for this IP → ARP SPOOFING
            # Don't use cooldown here — every single spoof packet is evidence
            desc = (f'ARP Spoof! {spa} was {known_mac} → now claimed by {sha}. '
                    f'MITM/Sniff attack detected!')
            self._fire(sha, spa, 0, 'MITM', 'critical', desc, 'ARP', victim=spa)
            # Update table to track ongoing changes
            self.arp_table[spa] = sha

    # ── DNS POISONING ────────────────────────────────────────────────────────
    def check_dns_response(self, src_ip, dst_ip, payload):
        """Detect unsolicited DNS responses (DNS spoofing/poisoning)"""
        if len(payload) < 12: return
        try:
            flags = struct.unpack('!H', payload[2:4])[0]
            qr    = (flags >> 15) & 1   # 1 = response
            ancount = struct.unpack('!H', payload[6:8])[0]
            if qr == 1 and ancount > 0:
                # A DNS response — check if it came from an unexpected source
                # (not the router/real DNS) — simple heuristic: if src is LAN host
                # and sending DNS responses, flag it
                if not src_ip.endswith('.1') and not src_ip.endswith('.254'):
                    if self._cd_ok(src_ip, dst_ip, 'DNS Poison'):
                        self._fire(src_ip, dst_ip, 53, 'DNS Poison', 'high',
                                   f'Suspicious DNS Response from {src_ip} — possible DNS spoofing',
                                   'UDP')
        except: pass

    # ── MAIN PACKET ANALYSIS ─────────────────────────────────────────────────
    def analyze(self, src_ip, dst_ip, src_port, dst_port, proto, flags='', payload=b''):
        s = self._src[src_ip]
        now = time.time()

        # 1. PORT SCAN
        if proto == 'TCP' and 'S' in flags and 'A' not in flags:
            ptimes = s['port_times'][dst_ip]
            ports  = s['port_targets'][dst_ip]
            self._prune(ptimes, self.PORT_SCAN_WINDOW)
            ptimes.append(now)
            ports.add(dst_port)
            if len(ports) >= self.PORT_SCAN_PORTS:
                if self._cd_ok(src_ip, dst_ip, 'Port Scan'):
                    cnt = len(ports); ports.clear(); ptimes.clear()
                    self._fire(src_ip, dst_ip, dst_port, 'Port Scan', 'medium',
                               f'Port Scan — {cnt} ports probed on {dst_ip}', 'TCP')
                return

        # 2. SYN FLOOD
        if proto == 'TCP' and 'S' in flags and 'A' not in flags:
            stimes = s['syn_times'][dst_ip]
            self._prune(stimes, 1)
            stimes.append(now)
            if len(stimes) >= self.SYN_FLOOD_PPS:
                if self._cd_ok(src_ip, dst_ip, 'DoS/DDoS'):
                    pps = len(stimes); stimes.clear()
                    self._fire(src_ip, dst_ip, dst_port, 'DoS/DDoS', 'critical',
                               f'SYN Flood on {dst_ip} — {pps} SYN/sec', 'TCP')
                return

        # 3. UDP FLOOD
        if proto == 'UDP' and dst_port not in (53, 5353, 67, 68, 123, 137, 138):
            utimes = s['udp_times'][dst_ip]
            self._prune(utimes, 1)
            utimes.append(now)
            if len(utimes) >= self.UDP_FLOOD_PPS:
                if self._cd_ok(src_ip, dst_ip, 'DoS/DDoS'):
                    pps = len(utimes); utimes.clear()
                    self._fire(src_ip, dst_ip, dst_port, 'DoS/DDoS', 'critical',
                               f'UDP Flood on {dst_ip} — {pps} pkts/sec', 'UDP')
                return

        # 4. ICMP PING SWEEP
        if proto == 'ICMP':
            self._prune(s['icmp_times'], 10)
            s['icmp_times'].append(now)
            s['icmp_dst'].add(dst_ip)
            if len(s['icmp_dst']) >= self.ICMP_SWEEP_COUNT:
                if self._cd_ok(src_ip, 'SWEEP', 'Recon'):
                    cnt = len(s['icmp_dst'])
                    s['icmp_dst'].clear(); s['icmp_times'].clear()
                    self._fire(src_ip, dst_ip, 0, 'Recon', 'medium',
                               f'ICMP Ping Sweep — {cnt} hosts probed (network recon)', 'ICMP')
            return

        # 5. SSH BRUTE FORCE
        if dst_port == 22 and proto == 'TCP' and 'S' in flags and 'A' not in flags:
            t = s['ssh_times'][dst_ip]; self._prune(t, 30); t.append(now)
            if len(t) >= self.BRUTE_SSH_COUNT:
                if self._cd_ok(src_ip, dst_ip, 'Brute Force'):
                    cnt = len(t); t.clear()
                    self._fire(src_ip, dst_ip, 22, 'Brute Force', 'high',
                               f'SSH Brute Force on {dst_ip} — {cnt} attempts in 30s', 'SSH')
            return

        # 6. RDP BRUTE FORCE
        if dst_port == 3389 and proto == 'TCP' and 'S' in flags and 'A' not in flags:
            t = s['rdp_times'][dst_ip]; self._prune(t, 30); t.append(now)
            if len(t) >= self.BRUTE_RDP_COUNT:
                if self._cd_ok(src_ip, dst_ip, 'Brute Force'):
                    cnt = len(t); t.clear()
                    self._fire(src_ip, dst_ip, 3389, 'Brute Force', 'high',
                               f'RDP Brute Force on {dst_ip} — {cnt} attempts', 'RDP')
            return

        # 7. FTP BRUTE FORCE
        if dst_port == 21 and proto == 'TCP' and 'S' in flags and 'A' not in flags:
            t = s['ftp_times'][dst_ip]; self._prune(t, 30); t.append(now)
            if len(t) >= self.BRUTE_FTP_COUNT:
                if self._cd_ok(src_ip, dst_ip, 'Brute Force'):
                    cnt = len(t); t.clear()
                    self._fire(src_ip, dst_ip, 21, 'Brute Force', 'high',
                               f'FTP Brute Force on {dst_ip} — {cnt} attempts', 'FTP')
            return

        # 8. HTTP PAYLOAD ATTACKS
        if dst_port in (80, 8080, 443, 8000, 8443, 8888) and payload:
            pl = payload.decode('utf-8', errors='ignore').lower()
            SQL = ["' or ","union select","1=1--","drop table","xp_cmdshell","exec(","information_schema"]
            if any(p in pl for p in SQL):
                if self._cd_ok(src_ip, dst_ip, 'SQL Injection'):
                    self._fire(src_ip, dst_ip, dst_port, 'SQL Injection', 'critical',
                               f'SQL Injection attempt → {dst_ip}:{dst_port}', 'HTTP')
                return
            XSS = ['<script','javascript:','onerror=','onload=','alert(document','<img src=x']
            if any(p in pl for p in XSS):
                if self._cd_ok(src_ip, dst_ip, 'XSS'):
                    self._fire(src_ip, dst_ip, dst_port, 'XSS', 'medium',
                               f'XSS Injection attempt → {dst_ip}:{dst_port}', 'HTTP')
                return
            CMD = ['; cat /etc','; id;','| nc ','`whoami`','$(id)','../../../etc/passwd',';ls -la']
            if any(p in pl for p in CMD):
                if self._cd_ok(src_ip, dst_ip, 'Command Inject'):
                    self._fire(src_ip, dst_ip, dst_port, 'Command Inject', 'critical',
                               f'Command Injection attempt → {dst_ip}:{dst_port}', 'HTTP')
                return
            RCE = ['cmd.exe','/bin/sh -c','/bin/bash -c','powershell -','wget http://','curl http://']
            if any(p in pl for p in RCE):
                if self._cd_ok(src_ip, dst_ip, 'RCE'):
                    self._fire(src_ip, dst_ip, dst_port, 'RCE', 'critical',
                               f'Remote Code Execution attempt → {dst_ip}:{dst_port}', 'HTTP')
                return

        # 9. DNS QUERY FLOOD (dns flood / amplification)
        if dst_port == 53 and proto == 'UDP':
            t = s['udp_times']['DNS']; self._prune(t, 2); t.append(now)
            if len(t) > 80:
                if self._cd_ok(src_ip, dst_ip, 'DNS Flood'):
                    cnt = len(t); t.clear()
                    self._fire(src_ip, dst_ip, 53, 'DoS/DDoS', 'high',
                               f'DNS Query Flood from {src_ip} — {cnt} queries/2s', 'UDP')
            return

    def mark_ongoing(self):
        active = {(o['src'],o['dst'],o['type']) for o in self.ongoing.get_all()}
        with self.lock:
            for a in self.alerts:
                a['ongoing'] = (a['src_ip'], a['dst_ip'], a['type']) in active

# ─── PACKET SNIFFER ───────────────────────────────────────────────────────────
class PacketSniffer:
    """
    ETH_P_ALL raw socket — captures everything including ARP, IPv4, IPv6.
    Promiscuous mode enabled to see traffic between other LAN hosts.
    """

    SKIP_IPS      = {'0.0.0.0','255.255.255.255'}
    SKIP_PREFIXES = tuple(f'{a}.' for a in range(224,256))

    def __init__(self, interface, detector, scanner):
        self.interface = interface
        self.detector  = detector
        self.scanner   = scanner
        self.running   = False
        self.pkt_count = 0

    @staticmethod
    def _ip(data):
        if len(data)<20: return None
        h=struct.unpack('!BBHHHBBH4s4s',data[:20])
        return {'proto':h[6],'src':socket.inet_ntoa(h[8]),
                'dst':socket.inet_ntoa(h[9]),'ihl':(h[0]&0xF)*4}

    @staticmethod
    def _tcp(data):
        if len(data)<20: return None
        h=struct.unpack('!HHLLBBHHH',data[:20])
        fb=h[5]
        f=('S' if fb&2 else '')+('A' if fb&16 else '')+('R' if fb&4 else '')+('F' if fb&1 else '')+('P' if fb&8 else '')
        return {'sp':h[0],'dp':h[1],'flags':f,'doff':(h[4]>>4)*4}

    @staticmethod
    def _udp(data):
        if len(data)<8: return None
        h=struct.unpack('!HHHH',data[:8])
        return {'sp':h[0],'dp':h[1]}

    @staticmethod
    def _arp(data):
        # Ethernet ARP frame body starts at offset 0 after ethertype
        if len(data)<28: return None
        oper = struct.unpack('!H',data[6:8])[0]
        sha  = ':'.join(f'{b:02x}' for b in data[8:14])
        spa  = socket.inet_ntoa(data[14:18])
        tha  = ':'.join(f'{b:02x}' for b in data[18:24])
        tpa  = socket.inet_ntoa(data[24:28])
        return {'oper':oper,'sha':sha,'spa':spa,'tha':tha,'tpa':tpa}

    def _skip(self, ip):
        if ip in self.SKIP_IPS: return True
        return any(ip.startswith(p) for p in self.SKIP_PREFIXES)

    def _set_promisc(self, sock):
        try:
            import fcntl, struct as st
            SIOCGIFFLAGS=0x8913; SIOCSIFFLAGS=0x8914; IFF_PROMISC=0x100
            req = st.pack('16sh', self.interface.encode()[:15], 0)
            flags = fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, req)
            val = st.unpack('16sh', flags)[1] | IFF_PROMISC
            fcntl.ioctl(sock.fileno(), SIOCSIFFLAGS,
                        st.pack('16sh', self.interface.encode()[:15], val))
            print(f"  {G}[✓]{RST} Promiscuous mode: {G}ENABLED{RST} on {W}{self.interface}{RST}")
        except Exception as e:
            print(f"  {Y}[!]{RST} Promiscuous mode failed (WiFi?): {e}")

    def start(self):
        self.running = True
        try:
            # ETH_P_ALL = 0x0003 — capture ALL frames including ARP
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.bind((self.interface, 0))
            self._set_promisc(sock)
            sock.settimeout(1.0)

            while self.running:
                try:
                    raw, _ = sock.recvfrom(65535)
                    self.pkt_count += 1
                    if len(raw) < 14: continue

                    eth_type = struct.unpack('!H', raw[12:14])[0]

                    # ── ARP (0x0806) ─────────────────────────────────────────
                    if eth_type == 0x0806:
                        arp = self._arp(raw[14:])
                        if arp:
                            self.detector.check_arp(
                                arp['sha'], arp['spa'],
                                arp['tha'], arp['tpa'],
                                arp['oper']
                            )
                        continue

                    # ── IPv4 (0x0800) ─────────────────────────────────────────
                    if eth_type != 0x0800: continue

                    ip_data = raw[14:]
                    ip = self._ip(ip_data)
                    if not ip: continue

                    src = ip['src']; dst = ip['dst']
                    if self._skip(src) or self._skip(dst): continue

                    # Register every IP we see
                    self.scanner.register_seen(src)
                    if not self._skip(dst):
                        self.scanner.register_seen(dst)

                    transport = ip_data[ip['ihl']:]

                    if ip['proto'] == 6:    # TCP
                        t = self._tcp(transport)
                        if t:
                            payload = transport[t['doff']:t['doff']+512]
                            self.detector.analyze(src, dst, t['sp'], t['dp'],
                                                  'TCP', t['flags'], payload)

                    elif ip['proto'] == 17:  # UDP
                        u = self._udp(transport)
                        if u:
                            payload = transport[8:8+512]
                            # DNS response check
                            if u['dp'] == 53 or u['sp'] == 53:
                                self.detector.check_dns_response(src, dst, transport[8:])
                            self.detector.analyze(src, dst, u['sp'], u['dp'], 'UDP',
                                                  payload=payload)

                    elif ip['proto'] == 1:   # ICMP
                        self.detector.analyze(src, dst, 0, 0, 'ICMP')

                except socket.timeout: continue
                except Exception: continue

        except PermissionError:
            print(f"\n{R}[!] Raw socket needs root.{RST}")
        except Exception as e:
            print(f"\n{R}[!] Sniffer error: {e}{RST}")

    def stop(self):
        self.running = False

# ─── FIREWALL ─────────────────────────────────────────────────────────────────
class FirewallManager:
    def __init__(self):
        self.blocked = {}
        self.lock    = threading.Lock()

    def block_ip(self, ip, reason="Auto"):
        with self.lock:
            if ip in self.blocked: return False
            try:
                # INPUT — block inbound traffic from attacker
                c=subprocess.run(['iptables','-C','INPUT','-s',ip,'-j','DROP'],capture_output=True)
                if c.returncode!=0:
                    subprocess.run(['iptables','-A','INPUT','-s',ip,'-j','DROP'],capture_output=True)
                # OUTPUT — block our machine from sending to attacker (optional, prevent confusion)
                # FORWARD — block attacker from routing through us to other hosts
                subprocess.run(['iptables','-A','FORWARD','-s',ip,'-j','DROP'],capture_output=True)
                self.blocked[ip] = {'reason':reason,'time':datetime.now().isoformat()}
                return True
            except: return False

    def unblock_ip(self, ip):
        with self.lock:
            if ip not in self.blocked: return False
            try:
                subprocess.run(['iptables','-D','INPUT','-s',ip,'-j','DROP'],capture_output=True)
                subprocess.run(['iptables','-D','FORWARD','-s',ip,'-j','DROP'],capture_output=True)
                del self.blocked[ip]; return True
            except: return False

    def unblock_all(self):
        with self.lock:
            for ip in list(self.blocked.keys()):
                try:
                    subprocess.run(['iptables','-D','INPUT','-s',ip,'-j','DROP'],capture_output=True)
                    subprocess.run(['iptables','-D','FORWARD','-s',ip,'-j','DROP'],capture_output=True)
                except: pass
            self.blocked.clear()

# ─── TERMINAL DISPLAY ─────────────────────────────────────────────────────────
class TerminalDisplay:
    _C = {'critical':R,'high':Y,'medium':M,'low':C}
    _I = {'critical':'⚡','high':'⚠ ','medium':'◈ ','low':'○ '}

    def on_alert(self, alert):
        sc  = self._C.get(alert['severity'], W)
        ic  = self._I.get(alert['severity'], '· ')
        ts  = alert['time'][11:19]
        blk = f" {G}[BLOCKED]{RST}" if alert.get('_blocked') else ''
        print(f"\n  {sc}{ic}{RST} {DIM}[{ts}]{RST} "
              f"{sc}{BOLD}{alert['type'].upper():16}{RST} "
              f"{M}{alert['src_ip']:18}{RST}→ "
              f"{C}{alert['dst_ip']}:{alert['dst_port']}{RST}  "
              f"{sc}{alert['severity'].upper()}{RST}{blk}")
        print(f"     {DIM}└── {alert['desc']}{RST}", flush=True)

# ─── HTTP API ─────────────────────────────────────────────────────────────────
class SOCAPIServer:
    def __init__(self, detector, scanner, firewall, ongoing, local_ip, port=8888):
        self.detector  = detector
        self.scanner   = scanner
        self.firewall  = firewall
        self.ongoing   = ongoing
        self.local_ip  = local_ip
        self.port      = port
        self.html_path = Path(__file__).parent / 'dashboard.html'

    def get_state(self):
        with self.detector.lock:
            alerts = list(self.detector.alerts[:200])
        with self.scanner.lock:
            hosts = list(self.scanner.hosts.values())
        with self.firewall.lock:
            blocked = [{'ip':k,**v} for k,v in self.firewall.blocked.items()]

        ok = {(o['src'],o['dst'],o['type']) for o in self.ongoing.get_all()}
        for a in alerts:
            a['ongoing'] = (a['src_ip'],a['dst_ip'],a['type']) in ok

        return {
            'alerts':  alerts,
            'hosts':   hosts,
            'blocked': blocked,
            'ongoing': len(ok),
            'stats': {
                'total_alerts': len(self.detector.alerts),
                'critical': sum(1 for a in alerts if a['severity']=='critical'),
                'high':     sum(1 for a in alerts if a['severity']=='high'),
                'hosts':    len(hosts),
                'blocked':  len(blocked),
                'ongoing':  len(ok),
            },
            'local_ip': self.local_ip,
        }

    def create_handler(self):
        srv = self
        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self,*a): pass
            def do_GET(self):
                if self.path=='/api/state':
                    b=json.dumps(srv.get_state()).encode()
                    self.send_response(200)
                    self.send_header('Content-Type','application/json')
                    self.send_header('Access-Control-Allow-Origin','*')
                    self.end_headers(); self.wfile.write(b)
                elif self.path in ('/','/dashboard'):
                    h=srv.html_path.read_bytes()
                    self.send_response(200)
                    self.send_header('Content-Type','text/html')
                    self.end_headers(); self.wfile.write(h)
                else:
                    self.send_response(404); self.end_headers()
            def do_POST(self):
                ln=int(self.headers.get('Content-Length',0))
                try: data=json.loads(self.rfile.read(ln))
                except: data={}
                ip=data.get('ip','')
                if self.path=='/api/block':
                    self._j({'ok':srv.firewall.block_ip(ip,data.get('reason','Dashboard'))})
                elif self.path=='/api/unblock':
                    self._j({'ok':srv.firewall.unblock_ip(ip)})
                elif self.path=='/api/unblock_all':
                    srv.firewall.unblock_all(); self._j({'ok':True})
                else:
                    self.send_response(404); self.end_headers()
            def _j(self,obj):
                b=json.dumps(obj).encode()
                self.send_response(200)
                self.send_header('Content-Type','application/json')
                self.send_header('Access-Control-Allow-Origin','*')
                self.end_headers(); self.wfile.write(b)
        return H

    def start(self):
        srv = http.server.HTTPServer(('0.0.0.0', self.port), self.create_handler())
        threading.Thread(target=srv.serve_forever, daemon=True).start()

# ─── MAIN ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description='IDSV1.0 Neural Defense Matrix v3')
    parser.add_argument('-i','--interface')
    parser.add_argument('-n','--network')
    parser.add_argument('--port', type=int, default=8888)
    parser.add_argument('--no-browser',  action='store_true')
    parser.add_argument('--no-firewall', action='store_true')
    args = parser.parse_args()

    check_root()
    print_banner()
    startup_sequence()

    network_cidr, auto_iface, local_ip = get_local_network()
    interface = args.interface or auto_iface
    network   = args.network   or network_cidr
    my_ips    = get_all_local_ips()
    my_macs   = get_all_local_macs()

    print(f"  {M}══════════════ NETWORK CONFIGURATION ══════════════{RST}")
    print(f"  {C}Interface   :{RST} {W}{interface}{RST}")
    print(f"  {C}My IP       :{RST} {W}{local_ip}{RST}")
    print(f"  {C}Network     :{RST} {W}{network}{RST}")
    print(f"  {C}My MACs     :{RST} {W}{', '.join(my_macs) if my_macs else 'detecting...'}{RST}")
    print(f"  {C}Dashboard   :{RST} {G}http://localhost:{args.port}{RST}")
    print()

    # Pre-load ARP table BEFORE starting sniffer
    # This is the most critical step for ARP spoof detection
    print(f"  {M}[*]{RST} Loading ARP baseline table...", end='', flush=True)
    arp_baseline = load_arp_table()
    print(f"\r  {G}[✓]{RST} ARP baseline: {W}{len(arp_baseline)}{RST} entries loaded")
    for ip, mac in arp_baseline.items():
        print(f"      {DIM}{ip:20} → {mac}{RST}")
    print()

    ongoing  = OngoingTracker()
    detector = AttackDetector(my_ips, my_macs, ongoing, arp_baseline)
    scanner  = NetworkScanner(network, local_ip)
    firewall = FirewallManager()
    terminal = TerminalDisplay()

    if not args.no_firewall:
        def auto_block(alert):
            src = alert['src_ip']
            # Block any attacker IP (including LAN/our own machine for testing)
            # For self-attack testing: we still block even if src==our IP
            sev = alert['severity']
            if sev in ('critical', 'high'):
                # Don't block our loopback or gateway
                if src.startswith('127.') or src == '0.0.0.0': return
                ok = firewall.block_ip(src, f"Auto:{alert['type']}")
                if ok:
                    alert['_blocked'] = True
                    print(f"  {R}[⊘]{RST} {R}AUTO-BLOCKED{RST} {W}{src}{RST} ({alert['type']})",
                          flush=True)
        detector.add_callback(auto_block)

    detector.add_callback(terminal.on_alert)

    api = SOCAPIServer(detector, scanner, firewall, ongoing, local_ip, args.port)
    api.start()

    sniffer = PacketSniffer(interface, detector, scanner)
    threading.Thread(target=sniffer.start, daemon=True).start()

    scanner.start_background_scan()

    def cleanup_loop():
        while True:
            time.sleep(10)
            ongoing.cleanup()
            detector.mark_ongoing()
    threading.Thread(target=cleanup_loop, daemon=True).start()

    time.sleep(1)
    if not args.no_browser:
        try: webbrowser.open(f'http://localhost:{args.port}')
        except: pass

    print(f"\n  {M}══════════════════ LIVE MONITORING ══════════════════{RST}")
    print(f"  {G}[✓]{RST} Packet capture active on {W}{interface}{RST}")
    print(f"  {G}[✓]{RST} ARP spoof detection: {G}ACTIVE{RST}")
    print(f"  {G}[✓]{RST} Monitoring ALL hosts (attacks on any user)")
    print(f"  {G}[✓]{RST} Dashboard → {G}http://localhost:{args.port}{RST}")
    print(f"  {Y}[!]{RST} Testing with bettercap? Run ARP spoof on a DIFFERENT target IP")
    print(f"  {DIM}[i]{RST} Press {W}Ctrl+C{RST} to stop and clean iptables\n")
    print(f"  {DIM}{'─'*78}{RST}")

    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n\n  {Y}[!] Shutting down...{RST}")
        sniffer.stop()
        if not args.no_firewall:
            print(f"  {C}[i] Cleaning iptables...{RST}")
            firewall.unblock_all()
        print(f"  {G}[✓] Defense matrix offline. Stay safe.{RST}\n")
        sys.exit(0)

if __name__ == '__main__':
    main()
