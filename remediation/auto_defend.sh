#!/bin/bash
# =============================================================================
# auto_defend.sh — Automated Remediation for vsftpd 2.3.4 Backdoor
# Clash of Teams 101 | Blue Team Automation
# Date: 17 February 2026
# =============================================================================
# Usage: sudo bash auto_defend.sh
# Run on the TARGET (Metasploitable) machine as root.
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

banner() {
    echo -e "${BLUE}"
    echo "=================================================="
    echo "  auto_defend.sh — Blue Team Automated Response"
    echo "  vsftpd 2.3.4 Backdoor (CVE-2011-2523)"
    echo "=================================================="
    echo -e "${NC}"
}

log_action() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[-]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root."
        exit 1
    fi
}

# --- Step 1: Kill vsftpd ---
kill_vsftpd() {
    echo ""
    log_action "STEP 1: Terminating vsftpd processes..."
    VSFTPD_PIDS=$(pgrep vsftpd 2>/dev/null || true)
    if [ -n "$VSFTPD_PIDS" ]; then
        kill -9 $VSFTPD_PIDS 2>/dev/null && log_action "vsftpd killed (PIDs: $VSFTPD_PIDS)"
    else
        log_warn "vsftpd not currently running."
    fi
}

# --- Step 2: Kill xinetd (prevents vsftpd respawn) ---
kill_xinetd() {
    echo ""
    log_action "STEP 2: Terminating xinetd (prevents service respawn)..."
    if killall xinetd 2>/dev/null; then
        log_action "xinetd terminated."
    else
        log_warn "xinetd not running."
    fi
}

# --- Step 3: Kill any backdoor shell on port 6200 ---
kill_backdoor_shell() {
    echo ""
    log_action "STEP 3: Killing any active backdoor shell on port 6200..."
    BACKDOOR_PIDS=$(fuser 6200/tcp 2>/dev/null || true)
    if [ -n "$BACKDOOR_PIDS" ]; then
        kill -9 $BACKDOOR_PIDS 2>/dev/null && log_action "Backdoor shell killed (PIDs: $BACKDOOR_PIDS)"
    else
        log_warn "No process found listening on port 6200."
    fi
}

# --- Step 4: Apply iptables DROP rules ---
apply_firewall_rules() {
    echo ""
    log_action "STEP 4: Applying iptables firewall rules..."

    # Drop all incoming connections to FTP (port 21)
    iptables -A INPUT -p tcp --dport 21 -j DROP
    log_action "iptables DROP rule added: port 21/tcp (FTP)"

    # Drop backdoor port
    iptables -A INPUT -p tcp --dport 6200 -j DROP
    log_action "iptables DROP rule added: port 6200/tcp (vsftpd backdoor)"

    # Block other known critical Metasploitable backdoors
    iptables -A INPUT -p tcp --dport 1524 -j DROP
    log_action "iptables DROP rule added: port 1524/tcp (bindshell)"

    iptables -A INPUT -p tcp --dport 6667 -j DROP
    log_action "iptables DROP rule added: port 6667/tcp (UnrealIRCd backdoor)"

    echo ""
    log_action "Current iptables INPUT chain:"
    iptables -L INPUT --line-numbers
}

# --- Step 5: Disable anonymous FTP in vsftpd.conf ---
disable_anonymous_ftp() {
    echo ""
    log_action "STEP 5: Disabling anonymous FTP in /etc/vsftpd.conf..."
    CONF="/etc/vsftpd.conf"
    if [ -f "$CONF" ]; then
        # Backup first
        cp "$CONF" "${CONF}.bak.$(date +%Y%m%d_%H%M%S)"
        log_action "Config backed up."

        # Disable anonymous_enable
        sed -i 's/^anonymous_enable=YES/anonymous_enable=NO/' "$CONF"
        log_action "anonymous_enable set to NO."
    else
        log_warn "/etc/vsftpd.conf not found — skipping."
    fi
}

# --- Step 6: Verification ---
verify_remediation() {
    echo ""
    echo -e "${BLUE}=================================================="
    echo "  VERIFICATION"
    echo -e "==================================================${NC}"

    echo ""
    log_action "Checking for vsftpd processes:"
    pgrep vsftpd && log_warn "vsftpd still running!" || log_action "vsftpd: NOT running ✓"

    echo ""
    log_action "Checking port 21 status:"
    ss -tlnp | grep ':21 ' && log_warn "Something still listening on port 21!" || log_action "Port 21: NOT listening ✓"

    echo ""
    log_action "Checking port 6200 status:"
    ss -tlnp | grep ':6200 ' && log_warn "Backdoor shell still active on 6200!" || log_action "Port 6200: NOT listening ✓"

    echo ""
    log_action "iptables rules summary:"
    iptables -L INPUT -n | grep -E "21|6200|1524|6667" || log_warn "No matching DROP rules found in INPUT chain."

    echo ""
    echo -e "${GREEN}=================================================="
    echo "  Remediation Complete."
    echo "  Re-run: nmap <this_ip> -p 21 from attacker to confirm 'filtered'."
    echo -e "==================================================${NC}"
}

# --- Persist rules (optional, requires iptables-persistent) ---
persist_rules() {
    echo ""
    log_action "STEP 7: Attempting to persist iptables rules..."
    if command -v iptables-save &>/dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null \
            && log_action "Rules saved to /etc/iptables/rules.v4" \
            || log_warn "Could not save — install iptables-persistent for persistence."
    else
        log_warn "iptables-save not found. Rules will NOT persist after reboot."
        log_warn "Run: apt-get install iptables-persistent && iptables-save > /etc/iptables/rules.v4"
    fi
}

# ======= MAIN =======
banner
check_root
kill_vsftpd
kill_xinetd
kill_backdoor_shell
apply_firewall_rules
disable_anonymous_ftp
persist_rules
verify_remediation
