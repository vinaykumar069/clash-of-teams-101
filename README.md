# 🔴🔵 Clash of Teams 101 — Breach & Defend

> **Cyber Security Project | DevTown | Submitted: 17 February 2026**

A full adversarial simulation exercise demonstrating a multi-stage attack lifecycle against a Metasploitable 2 target — from initial reconnaissance through exploitation to root access — followed by blue team detection, analysis, and hardened remediation.

---

## 🗂️ Repository Structure

```
clash-of-teams/
├── README.md                          ← This file (Purple Team overview)
├── red-team/
│   └── red_team_report.md             ← Attack walkthrough (Recon → Exploit → Root)
├── blue-team/
│   └── blue_team_report.md            ← Detection & log analysis
├── remediation/
│   ├── remediation_report.md          ← Containment & hardening steps
│   └── auto_defend.sh                 ← Automated firewall defence script
├── scripts/
│   └── log_analyzer.py                ← Python script to parse IoCs from logs
├── evidence/
│   ├── logs/
│   │   ├── nmapscan.txt               ← Nmap -sS -A -T4 scan output
│   │   ├── vsftpd.log                 ← FTP server connection log
│   │   ├── auth.log                   ← SSH/PAM authentication log
│   │   └── netstat.txt                ← Active connection snapshot
│   └── screenshots/
│       ├── 01_vsftpd_exploit_root_shell.png
│       ├── 02_network_ifconfig.png
│       ├── 03_root_shell_ls.png
│       ├── 04_port21_kill_xinetd.png
│       ├── 05_nmap_port21_closed.png
│       ├── 06_iptables_drop_rule.png
│       ├── 07_iptables_verified_filtered.png
│       └── 08_exploit_failed_after_remediation.png
└── after_action_report.md             ← Final Purple Team summary & lessons learned
```

---

## 🎯 Lab Environment

| Component | Details |
|-----------|---------|
| **Attacker** | Kali Linux — IP `10.63.233.26` |
| **Target** | Metasploitable 2 — IP `10.63.233.95` |
| **Network** | Host-only / NAT — subnet `10.63.233.0/24` |
| **Hypervisor** | Oracle VirtualBox |
| **Tools Used** | Nmap 7.98, Metasploit v6.4.110-dev, iptables, vsftpd, xinetd |

---

## ⚡ TL;DR Attack Chain

```
Recon (Nmap)  →  vsftpd 2.3.4 Backdoor (MSF)  →  Root Shell (port 6200)
     ↓
Blue Team detects via vsftpd.log + auth.log IoCs
     ↓
Remediation: Kill vsftpd → Kill xinetd → iptables DROP port 21
     ↓
Verification: Exploit fails — "Connection timed out"
```

---

## 📊 Purple Team Correlation Table

| Time (UTC+5:30) | Red Team Action | Blue Team Observable |
|-----------------|-----------------|----------------------|
| 15:51:06 | Metasploit `exploit` triggered on port 21 | `vsftpd.log`: CONNECT from `10.63.233.26` |
| 15:51:06 | Backdoor spawned on port 6200 | `vsftpd.log`: Anonymous `OK LOGIN` (IEUser@) |
| 15:51:06 | Root shell session opened | `auth.log`: rshd/rlogind connections from attacker IP |
| 05:38:34 | Second exploit attempt (Nmap scan) | `auth.log`: SSH version mismatch — `SSH-1.5-Nmap-SSH1-Hostkey` |
| 05:38:47 | Nmap NSE SSH probe | `auth.log`: `Protocol major versions differ for 10.63.233.26` |
| 17:36 | (Blue Team) vsftpd process killed | Port 21 becomes `closed` on Nmap rescan |
| 17:37 | (Blue Team) iptables DROP rule added | Port 21 becomes `filtered` on Nmap rescan |
| 17:39 | (Red Team) Re-exploit attempt | Metasploit: `[-] Exploit failed [unreachable]: Connection timed out` |

---

## 🔗 Quick Links

- [Red Team Report](red-team/red_team_report.md)
- [Blue Team Report](blue-team/blue_team_report.md)
- [Remediation Report](remediation/remediation_report.md)
- [After Action Report](after_action_report.md)
- [Auto-Defend Script](remediation/auto_defend.sh)
- [Log Analyzer Script](scripts/log_analyzer.py)
