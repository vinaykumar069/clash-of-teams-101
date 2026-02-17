# 🔵 Blue Team Report — Detection & Analysis

**Defender System:** Metasploitable 2 (`10.63.233.95`)  
**Attacker IP:** `10.63.233.26`  
**Analysis Date:** 17 February 2026  
**Log Sources:** `vsftpd.log`, `auth.log`, `netstat`, `nmapscan.txt`

---

## 1. Log Source Inventory

| Log File | Location | Contains |
|----------|----------|---------|
| `vsftpd.log` | `/var/log/vsftpd.log` | FTP connection and login records |
| `auth.log` | `/var/log/auth.log` | SSH, PAM, sudo, su authentication events |
| `netstat.txt` | Live snapshot | Active TCP/UDP connections at time of capture |
| `nmapscan.txt` | Kali attacker | Nmap scan output (used as Red Team recon artifact) |

All raw logs are preserved in [`evidence/logs/`](../evidence/logs/).

---

## 2. Timeline Reconstruction

### 2.1 Pre-Attack Baseline (May 2012)

The vsftpd.log shows historical legitimate FTP activity from `127.0.0.1` and `172.16.123.1` dating back to May 2012 — establishing a known-good baseline.

### 2.2 First Attacker Contact — 17 Feb 2026, 01:43 UTC

```
Tue Feb 17 01:43:21 2026 [pid 4781] CONNECT: Client "10.63.233.26"
Tue Feb 17 01:43:33 2026 [pid 4807] [ftp] OK LOGIN: Client "10.63.233.26", anon password "IEUser@"
```

**IoC:** The password `IEUser@` is the default anonymous password used by Metasploit's FTP exploit modules. Legitimate anonymous FTP clients typically send an email address.

### 2.3 Rapid Multi-Connection Burst — 01:43–01:45 UTC

```
Tue Feb 17 01:43:33 2026 [pid 4821] CONNECT: Client "10.63.233.26"
Tue Feb 17 01:43:33 2026 [pid 4825] CONNECT: Client "10.63.233.26"
Tue Feb 17 01:43:34 2026 [pid 4855] CONNECT: Client "10.63.233.26"
Tue Feb 17 01:45:20 2026 [pid 5053] CONNECT: Client "10.63.233.26"
Tue Feb 17 01:45:20 2026 [pid 5055] CONNECT: Client "10.63.233.26"
[... 6 simultaneous connections ...]
```

**IoC:** Multiple simultaneous connections in a burst pattern is characteristic of Metasploit's connection handling during exploit attempts. Normal FTP clients use a single connection.

### 2.4 Nmap Scan Detected — 05:38 UTC

From `auth.log`:

```
Feb 17 05:38:34 metasploitable sshd[4722]: Did not receive identification string from 10.63.233.26
Feb 17 05:38:34 metasploitable rshd[4729]: Connection from 10.63.233.26 on illegal port
Feb 17 05:38:40 metasploitable rlogind[4730]: Connection from 10.63.233.26 on illegal port
Feb 17 05:38:40 metasploitable rlogind[4752]: Connection from 10.63.233.26 on illegal port
Feb 17 05:38:47 metasploitable sshd[4800]: Protocol major versions differ for 10.63.233.26: SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1 vs. SSH-1.5-Nmap-SSH1-Hostkey
Feb 17 05:38:47 metasploitable sshd[4829]: Protocol major versions differ for 10.63.233.26: SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1 vs. SSH-1.5-NmapNSE_1.0
```

**IoC Analysis:**
- `Did not receive identification string` → TCP connect scan without completing SSH handshake
- `SSH-1.5-Nmap-SSH1-Hostkey` → Nmap's built-in SSH version detection script
- `SSH-1.5-NmapNSE_1.0` → Nmap Scripting Engine (NSE) running SSH-related scripts
- `rshd/rlogind` "illegal port" → Nmap scanning ports 512, 513, 514 (r-services), triggering connection from non-privileged ports

**Conclusion:** An aggressive Nmap scan (`-A` flag) was run from `10.63.233.26` at ~05:38 UTC.

### 2.5 Successful Exploitation — 15:51 UTC (10:21 AM UTC / 15:51 IST)

From `vsftpd.log`:
```
Tue Feb 17 05:08:30 2026 [pid 4784] CONNECT: Client "10.63.233.26"
Tue Feb 17 05:08:31 2026 [pid 4783] [ftp] OK LOGIN: Client "10.63.233.26", anon password "IEUser@"
Tue Feb 17 05:38:46 2026 [pid 4786] [ftp] OK LOGIN: Client "10.63.233.26", anon password "IEUser@"
```

Correlated with screenshot `01_vsftpd_exploit_root_shell.png`:
```
[*] Command shell session 1 opened (10.63.233.26:39963 → 10.63.233.95:6200) at 2026-02-17 15:51:06 +0530
```

**Backdoor Mechanism:** vsftpd 2.3.4 contains a backdoor introduced in July 2011 where including `:)` in the username causes the daemon to bind a shell to port 6200. The session connected from attacker port 39963 to target port 6200.

### 2.6 Privilege Escalation — Not Required

The vsftpd backdoor runs as root by design. The obtained shell immediately returned:
```
uid=0(root) gid=0(root)
```

No privilege escalation steps were needed — the service was already running with root privileges.

---

## 3. Indicators of Compromise (IoCs) Summary

| Category | IoC | Log Source | Timestamp |
|----------|-----|-----------|-----------|
| Recon | Nmap scan strings from `10.63.233.26` | auth.log | 05:38 UTC |
| Recon | `SSH-1.5-Nmap-SSH1-Hostkey` in SSH banner | auth.log | 05:38:47 |
| Recon | `rshd/rlogind` connections on illegal port | auth.log | 05:38:34–05:38:51 |
| Initial Access | Anonymous FTP CONNECT burst (6+ simultaneous) | vsftpd.log | 01:43, 05:08, 05:38 |
| Initial Access | Anon password `IEUser@` (Metasploit default) | vsftpd.log | Multiple |
| Exploitation | vsftpd backdoor triggered (port 6200 connection) | Screenshot | 15:51:06 |
| Post-Exploit | Root shell confirmed (`uid=0`) | Screenshot | 15:51:06 |

---

## 4. Attack Confirmed Via Log Cross-Correlation

```
vsftpd.log                     auth.log                    Screenshot Evidence
    |                               |                              |
CONNECT 10.63.233.26      SSH-1.5-Nmap* strings         Session opened port 6200
OK LOGIN IEUser@          rshd illegal port conns        uid=0(root) confirmed
Multiple burst connects   Protocol version mismatch      Root shell interactive
```

All three log sources independently corroborate the same attacker IP (`10.63.233.26`) performing coordinated reconnaissance and exploitation.

---

## 5. MITRE ATT&CK Mapping

| Technique ID | Technique Name | Observed |
|-------------|----------------|---------|
| T1595.001 | Active Scanning: Scanning IP Blocks | Nmap -sS scan |
| T1046 | Network Service Discovery | Nmap -A with version detection |
| T1190 | Exploit Public-Facing Application | vsftpd 2.3.4 backdoor |
| T1059.004 | Command & Scripting Interpreter: Unix Shell | Root bash shell via port 6200 |
| T1078 | Valid Accounts (Anonymous) | Anonymous FTP with `IEUser@` password |
