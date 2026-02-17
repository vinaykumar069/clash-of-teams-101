# 📋 After Action Report — Purple Team Summary

**Project:** Clash of Teams 101 — Breach & Defend  
**Submitted By:** Venkat  
**Date:** 17 February 2026  
**Target:** Metasploitable 2 (`10.63.233.95`)  
**Attacker Machine:** Kali Linux (`10.63.233.26`)

---

## 1. Executive Summary

This exercise simulated a realistic adversarial scenario where an attacker on the same network subnet exploited a known critical vulnerability in a legacy FTP service to gain full root access to the target system. The blue team subsequently detected the attack through log analysis, confirmed the compromise, and applied both immediate containment and layered defensive controls.

**Key Result:** The attacker achieved root shell access in under 3 minutes from initial scan. After blue team remediation, the same exploit failed with a connection timeout. The entire attack lifecycle was documented and correlated across multiple log sources.

---

## 2. Attack Summary (Red Team)

| Stage | Action | Outcome |
|-------|--------|---------|
| Reconnaissance | Nmap `-sS -A -T4` scan | 23 open ports identified |
| Vulnerability ID | vsftpd 2.3.4 on port 21 | CVE-2011-2523 confirmed |
| Exploitation | Metasploit `unix/ftp/vsftpd_234_backdoor` | Root shell on port 6200 |
| Post-Exploit | `whoami`, `uname -a`, `ls /` | uid=0, full filesystem access |

**Time from scan to root shell: < 3 minutes**

The vulnerability — a backdoor deliberately inserted into vsftpd 2.3.4 by an unknown actor — required zero authentication and granted immediate root access. No privilege escalation was needed.

---

## 3. Detection Summary (Blue Team)

Three log sources were used to independently confirm the attack:

**vsftpd.log indicators:**
- Anonymous login with password `IEUser@` (Metasploit's default FTP anonymous credential)
- Burst pattern of 6+ simultaneous connections from `10.63.233.26` within single seconds
- Multiple login events across several time windows (01:43, 05:08, 05:38 UTC)

**auth.log indicators:**
- `SSH-1.5-Nmap-SSH1-Hostkey` and `SSH-1.5-NmapNSE_1.0` in SSH banner exchange — definitive Nmap fingerprint
- `Did not receive identification string` — TCP connect scan touching SSH without completing handshake
- Multiple `rshd`/`rlogind` "Connection from ... on illegal port" — Nmap scanning r-services (ports 512–514)

**Screenshot evidence:**
- Root shell confirmation (`uid=0`, `whoami: root`)
- Metasploit session opened to port 6200
- Full filesystem access (`ls /`)

**Attacker IP confirmed:** `10.63.233.26` — appearing across all log sources consistently.

---

## 4. Remediation Summary

| Step | Command | Effect |
|------|---------|--------|
| Kill vsftpd | `kill -9 <PID>` | Stopped active FTP service |
| Kill xinetd | `killall xinetd` | Prevented vsftpd respawn |
| Block port 21 | `iptables -A INPUT -p tcp --dport 21 -j DROP` | Port 21: `open` → `filtered` |
| Block port 6200 | `iptables -A INPUT -p tcp --dport 6200 -j DROP` | Backdoor shell port blocked |
| Verify | Nmap rescan + re-run exploit | Exploit fails: "Connection timed out" |

All steps documented with screenshots in `evidence/screenshots/`.

---

## 5. Lessons Learned

### 5.1 Attacker Perspective
- Metasploit modules for known CVEs are extremely efficient — known backdoors in default installations represent the fastest possible attack path.
- Anonymous FTP is a significant risk factor; it enables unauthenticated interaction that triggers the backdoor.
- The `-A` Nmap flag leaves heavy fingerprints in logs (SSH banner exchanges, r-services probes) — stealth scans should use `-sS` alone for quieter reconnaissance.

### 5.2 Defender Perspective
- **Anonymous FTP passwords are a reliable IoC:** `IEUser@` is the hardcoded default in Metasploit's FTP modules. Any occurrence in vsftpd.log should trigger an alert.
- **Burst connection patterns are detectable:** 6 simultaneous FTP connections from a single IP within one second is abnormal for any legitimate client.
- **Nmap leaves persistent auth.log fingerprints:** The strings `SSH-1.5-Nmap-SSH1-Hostkey` and `NmapNSE` uniquely identify Nmap activity even when no exploit is used.
- **xinetd must be killed alongside vsftpd:** Killing only vsftpd is insufficient because xinetd will respawn it within seconds.
- **iptables DROP vs CLOSE:** A `closed` port still responds to TCP RST. Only a `DROP` (firewall rule) produces a `filtered` state that prevents any interaction.

### 5.3 Process Lessons
- Time correlation across log files was essential — the attacker IP appeared in three independent sources, providing high-confidence attribution.
- Log timestamps must be timezone-consistent for accurate correlation; the exercise revealed minor offsets between UTC and IST entries in different logs.
- Automated defence scripts can respond faster than manual intervention, especially when a service like xinetd can respawn a backdoored process within seconds.

---

## 6. Business Impact Assessment

If this breach had occurred in a production environment:

**Immediate Impact:**
- Complete server compromise — an attacker with root access can read, modify, or delete all data
- Credential harvesting — `/etc/shadow` (hashed passwords) accessible immediately
- Lateral movement — from a root shell, the attacker could pivot to other machines on the network
- Data exfiltration — any database contents (MySQL on port 3306, PostgreSQL on 5432) fully accessible

**Extended Impact:**
- All services running on the server (web, mail, DNS) would be compromised
- Customer data exposure — potential regulatory breach (GDPR, PCI-DSS depending on sector)
- Reputational damage and operational disruption
- Backdoor installation could persist even after the vsftpd vector is patched

**Estimated Response Cost:** A real incident of this severity would typically require 2–5 days of IR team effort, forensic imaging, full system rebuild, and regulatory notification — easily exceeding $50,000–$200,000 in total cost for a mid-sized organization.

---

## 7. Recommendations for Automated Future Defence

1. **SIEM Rule:** Alert on any `IEUser@` password in vsftpd.log — zero false positives expected in production.
2. **SIEM Rule:** Alert on `SSH-1.5-Nmap` in auth.log — immediate Nmap scan notification.
3. **Automated Block:** Integrate `auto_defend.sh` with a SIEM or IDS to trigger automatically on detection.
4. **Upgrade vsftpd:** Replace 2.3.4 with a current, patched version. Disable anonymous FTP entirely.
5. **Disable Legacy Services:** Remove or firewall-block telnet (23), rsh (512), rlogin (513), rexec (514) — none should exist in production.
6. **Network Segmentation:** FTP/legacy services should never be directly reachable from untrusted segments.
7. **Least Privilege:** vsftpd should not run as root; configure it to run as a dedicated low-privilege user.

---

## 8. Files Submitted

| File | Description |
|------|-------------|
| `README.md` | Purple Team overview and correlation table |
| `red-team/red_team_report.md` | Full attack walkthrough with commands |
| `blue-team/blue_team_report.md` | Detection analysis with IoC mapping |
| `remediation/remediation_report.md` | Step-by-step containment and hardening |
| `remediation/auto_defend.sh` | Automated defence script |
| `scripts/log_analyzer.py` | Python IoC extraction tool |
| `evidence/logs/` | Raw log files (vsftpd.log, auth.log, nmapscan.txt, netstat.txt) |
| `evidence/screenshots/` | 8 numbered screenshots covering full attack → defence lifecycle |
| `after_action_report.md` | This document |
