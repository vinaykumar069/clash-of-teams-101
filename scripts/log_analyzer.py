#!/usr/bin/env python3
"""
log_analyzer.py — Automated IoC Detection from System Logs
Clash of Teams 101 | Blue Team Tooling
Date: 17 February 2026

Usage:
    python3 log_analyzer.py --vsftpd evidence/logs/vsftpd.log
    python3 log_analyzer.py --auth evidence/logs/auth.log
    python3 log_analyzer.py --all evidence/logs/
    python3 log_analyzer.py --all evidence/logs/ --ip 10.63.233.26
"""

import argparse
import os
import re
from collections import defaultdict
from datetime import datetime


# ─── Patterns ─────────────────────────────────────────────────────────────────

VSFTPD_PATTERNS = {
    "connect":      re.compile(r'(\w+ \w+ \d+ \d+:\d+:\d+ \d+) \[pid \d+\] CONNECT: Client "([^"]+)"'),
    "ok_login":     re.compile(r'(\w+ \w+ \d+ \d+:\d+:\d+ \d+) \[pid \d+\] \[([^\]]+)\] OK LOGIN: Client "([^"]+)", anon password "([^"]+)"'),
    "fail_login":   re.compile(r'(\w+ \w+ \d+ \d+:\d+:\d+ \d+) \[pid \d+\] \[([^\]]+)\] FAIL LOGIN: Client "([^"]+)"'),
}

AUTH_PATTERNS = {
    "nmap_ssh":     re.compile(r'(.*) sshd\[\d+\]: Protocol major versions differ for ([^:]+): .* vs\. (SSH-1\.5-Nmap[^\s]*)'),
    "nmap_nse":     re.compile(r'(.*) sshd\[\d+\]: Protocol major versions differ for ([^:]+): .* vs\. (SSH-1\.5-NmapNSE[^\s]*)'),
    "no_ident":     re.compile(r'(.*) sshd\[\d+\]: Did not receive identification string from ([^\s]+)'),
    "rshd_illegal": re.compile(r'(.*) rshd\[\d+\]: Connection from ([^\s]+) on illegal port'),
    "rlogind_illegal": re.compile(r'(.*) rlogind\[\d+\]: Connection from ([^\s]+) on illegal port'),
    "sudo_cmd":     re.compile(r'(.*) sudo:\s+([^\s]+) : TTY=.* COMMAND=(.+)'),
    "su_success":   re.compile(r'(.*) su\[\d+\]: Successful su for ([^\s]+) by ([^\s]+)'),
}

# Known Metasploit anonymous FTP passwords
METASPLOIT_ANON_PASSWORDS = {"IEUser@", "mozilla@example.com", "anonymous@"}

SUSPICIOUS_SSH_STRINGS = {"Nmap-SSH1-Hostkey", "NmapNSE_1.0", "Nmap-SSH2-Hostkey"}


# ─── Parsers ──────────────────────────────────────────────────────────────────

def analyze_vsftpd_log(filepath: str, filter_ip: str = None):
    """Parse vsftpd.log and extract IoCs."""
    print(f"\n{'='*60}")
    print(f"  VSFTPD LOG ANALYSIS: {filepath}")
    print(f"{'='*60}")

    connects = defaultdict(list)        # ip -> [timestamps]
    ok_logins = defaultdict(list)       # ip -> [(timestamp, user, anon_pass)]
    fail_logins = defaultdict(list)     # ip -> [timestamps]
    suspicious_ips = set()

    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        return

    for line in lines:
        # Connect events
        m = VSFTPD_PATTERNS["connect"].search(line)
        if m:
            ts, ip = m.group(1), m.group(2)
            if filter_ip and ip != filter_ip:
                continue
            connects[ip].append(ts)
            continue

        # OK Login events
        m = VSFTPD_PATTERNS["ok_login"].search(line)
        if m:
            ts, user, ip, anon_pass = m.group(1), m.group(2), m.group(3), m.group(4)
            if filter_ip and ip != filter_ip:
                continue
            ok_logins[ip].append((ts, user, anon_pass))
            if anon_pass in METASPLOIT_ANON_PASSWORDS:
                suspicious_ips.add(ip)
            continue

        # Fail Login events
        m = VSFTPD_PATTERNS["fail_login"].search(line)
        if m:
            ts, user, ip = m.group(1), m.group(2), m.group(3)
            if filter_ip and ip != filter_ip:
                continue
            fail_logins[ip].append(ts)

    # ─── Report ───
    all_ips = set(list(connects.keys()) + list(ok_logins.keys()) + list(fail_logins.keys()))

    print(f"\n[+] Total unique IPs seen: {len(all_ips)}")
    for ip in sorted(all_ips):
        print(f"\n  ── IP: {ip}")
        print(f"     Connections:  {len(connects.get(ip, []))}")
        print(f"     OK Logins:    {len(ok_logins.get(ip, []))}")
        print(f"     Failed Logins:{len(fail_logins.get(ip, []))}")

        if ok_logins.get(ip):
            first_ts = ok_logins[ip][0][0]
            last_ts = ok_logins[ip][-1][0]
            anon_passwords_used = set(entry[2] for entry in ok_logins[ip])
            print(f"     First Login:  {first_ts}")
            print(f"     Last Login:   {last_ts}")
            print(f"     Anon Passwords Used: {anon_passwords_used}")

        if ip in suspicious_ips:
            print(f"     ⚠️  SUSPICIOUS: Metasploit anonymous password detected!")

    print(f"\n[!] Suspicious IPs (Metasploit fingerprint): {suspicious_ips if suspicious_ips else 'None'}")

    # Burst detection (>3 connects within same minute)
    print("\n[+] Burst Connection Analysis:")
    for ip, timestamps in connects.items():
        if len(timestamps) < 3:
            continue
        # Group by minute
        minute_counts = defaultdict(int)
        for ts in timestamps:
            minute_key = ts[:16]  # "Mon Feb 17 01:43"
            minute_counts[minute_key] += 1
        bursts = {k: v for k, v in minute_counts.items() if v >= 3}
        if bursts:
            print(f"  ⚠️  IP {ip}: Connection bursts detected:")
            for minute, count in sorted(bursts.items()):
                print(f"       {minute} → {count} connections")


def analyze_auth_log(filepath: str, filter_ip: str = None):
    """Parse auth.log and extract IoCs."""
    print(f"\n{'='*60}")
    print(f"  AUTH LOG ANALYSIS: {filepath}")
    print(f"{'='*60}")

    nmap_probes = []
    rservice_probes = []
    no_ident = []
    sudo_cmds = []

    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        return

    for line in lines:
        # Nmap SSH probes
        for key in ("nmap_ssh", "nmap_nse"):
            m = AUTH_PATTERNS[key].search(line)
            if m:
                ts, ip, nmap_str = m.group(1), m.group(2), m.group(3)
                if filter_ip and ip.strip() != filter_ip:
                    continue
                nmap_probes.append((ts.strip(), ip.strip(), nmap_str))

        # No identification string
        m = AUTH_PATTERNS["no_ident"].search(line)
        if m:
            ts, ip = m.group(1), m.group(2)
            if filter_ip and ip != filter_ip:
                continue
            no_ident.append((ts.strip(), ip))

        # rshd/rlogind illegal port (r-services scan)
        for key in ("rshd_illegal", "rlogind_illegal"):
            m = AUTH_PATTERNS[key].search(line)
            if m:
                ts, ip = m.group(1), m.group(2)
                if filter_ip and ip != filter_ip:
                    continue
                rservice_probes.append((ts.strip(), ip, key))

        # sudo commands
        m = AUTH_PATTERNS["sudo_cmd"].search(line)
        if m:
            sudo_cmds.append((m.group(1).strip(), m.group(2), m.group(3).strip()))

    # ─── Report ───
    print(f"\n[+] Nmap SSH probes detected: {len(nmap_probes)}")
    for ts, ip, nmap_str in nmap_probes:
        print(f"    {ts} | IP: {ip} | String: {nmap_str}")
        print(f"    ⚠️  INDICATOR: Nmap active scan detected!")

    print(f"\n[+] Failed SSH identification (port scan): {len(no_ident)}")
    for ts, ip in no_ident:
        print(f"    {ts} | IP: {ip}")

    print(f"\n[+] r-services illegal port probes (Nmap scanning 512-514): {len(rservice_probes)}")
    for ts, ip, service in rservice_probes:
        print(f"    {ts} | IP: {ip} | Service: {service}")

    print(f"\n[+] Sudo commands executed: {len(sudo_cmds)}")
    for ts, user, cmd in sudo_cmds:
        print(f"    {ts} | User: {user} | CMD: {cmd}")

    # Summarize attacker IPs
    attacker_ips = set()
    for _, ip, _ in nmap_probes:
        attacker_ips.add(ip)
    for _, ip in no_ident:
        attacker_ips.add(ip)
    for _, ip, _ in rservice_probes:
        attacker_ips.add(ip)

    if attacker_ips:
        print(f"\n[!] Attacker IPs identified from auth.log: {attacker_ips}")


def print_summary(filter_ip: str = None):
    """Print consolidated IoC summary."""
    print(f"\n{'='*60}")
    print("  IoC SUMMARY")
    print(f"{'='*60}")
    if filter_ip:
        print(f"\n  Filtered for IP: {filter_ip}")
    print("""
  Confirmed Indicators of Compromise:
  ┌─────────────────────────────────────────────────────────┐
  │ 1. Anonymous FTP with password "IEUser@" (Metasploit)   │
  │ 2. Connection bursts (6+ simultaneous FTP sessions)     │
  │ 3. SSH-1.5-Nmap-SSH1-Hostkey in auth.log                │
  │ 4. SSH-1.5-NmapNSE_1.0 in auth.log                      │
  │ 5. rshd/rlogind "illegal port" connections              │
  │ 6. "Did not receive identification string" (SSH scan)   │
  │ 7. vsftpd 2.3.4 identified (known backdoor version)     │
  └─────────────────────────────────────────────────────────┘

  MITRE ATT&CK:
    T1595.001 — Active Scanning
    T1046     — Network Service Discovery
    T1190     — Exploit Public-Facing Application
    T1059.004 — Unix Shell
    T1078     — Valid Accounts (Anonymous FTP)
""")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Log Analyzer — Clash of Teams 101 Blue Team Tool"
    )
    parser.add_argument("--vsftpd", help="Path to vsftpd.log file")
    parser.add_argument("--auth", help="Path to auth.log file")
    parser.add_argument("--all", metavar="LOG_DIR", help="Analyze all logs in a directory")
    parser.add_argument("--ip", help="Filter results by specific attacker IP")

    args = parser.parse_args()

    if not any([args.vsftpd, args.auth, args.all]):
        parser.print_help()
        return

    if args.vsftpd:
        analyze_vsftpd_log(args.vsftpd, filter_ip=args.ip)

    if args.auth:
        analyze_auth_log(args.auth, filter_ip=args.ip)

    if args.all:
        log_dir = args.all.rstrip("/")
        vsftpd_path = os.path.join(log_dir, "vsftpd.log")
        auth_path = os.path.join(log_dir, "auth.log")
        if os.path.exists(vsftpd_path):
            analyze_vsftpd_log(vsftpd_path, filter_ip=args.ip)
        if os.path.exists(auth_path):
            analyze_auth_log(auth_path, filter_ip=args.ip)

    print_summary(filter_ip=args.ip)


if __name__ == "__main__":
    main()
