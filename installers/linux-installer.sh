#!/bin/bash
# =============================================================================
# Wazuh Browser Monitor - Linux Installer
# Author  : Ram Kumar G (IT Fortress)
# Version : 2.0
# Supports: Ubuntu 20.04+, Debian 11+, AlmaLinux 8+, RHEL 8+, CentOS 8+
#
# VT-CLEAN: No internet downloads, no remote script fetching.
# Run as the user to monitor (no sudo needed for core setup).
# Sudo is only used to add the localfile block to ossec.conf.
# =============================================================================

set -e

# ── COLORS ────────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

# ── PATHS ─────────────────────────────────────────────────────────────────────
REPO_ROOT="$(dirname "$(dirname "$(realpath "$0")")")" 
SOURCE_SCRIPT="$REPO_ROOT/collector/browser-history-monitor.py"
INSTALL_DIR="$HOME/.browser-monitor"
DEST_SCRIPT="$INSTALL_DIR/browser-history-monitor.py"
LOG_FILE="$INSTALL_DIR/browser_history.log"
SERVICE_DIR="$HOME/.config/systemd/user"
SERVICE_FILE="$SERVICE_DIR/browser-monitor.service"
WAZUH_CONF="/var/ossec/etc/ossec.conf"

echo -e ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Wazuh Browser Monitor - Linux Installer                 ║${NC}"
echo -e "${BLUE}║  IT Fortress | VT-Clean | No Internet Downloads          ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo -e ""

# ── STEP 1: PYTHON CHECK ──────────────────────────────────────────────────────
echo -e "${YELLOW}[1] Checking Python 3...${NC}"
PYTHON_BIN=""
for py in python3 python3.12 python3.11 python3.10 python3.9 python3.8; do
    if command -v "$py" &>/dev/null; then
        PYTHON_BIN=$(command -v "$py")
        break
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo -e "${RED}[-] Python 3 not found.${NC}"
    if   command -v apt-get &>/dev/null; then echo "    Run: sudo apt install -y python3"
    elif command -v dnf     &>/dev/null; then echo "    Run: sudo dnf install -y python3"
    elif command -v yum     &>/dev/null; then echo "    Run: sudo yum install -y python3"
    fi
    exit 1
fi
echo -e "${GREEN}    [+] Python: $($PYTHON_BIN --version 2>&1) at $PYTHON_BIN${NC}"

# ── STEP 2: VERIFY SOURCE SCRIPT ──────────────────────────────────────────────
echo -e "${YELLOW}[2] Verifying collector script...${NC}"
if [ ! -f "$SOURCE_SCRIPT" ]; then
    echo -e "${RED}[-] Collector not found at: $SOURCE_SCRIPT${NC}"
    echo "    Make sure you cloned the full repo."
    exit 1
fi
echo -e "${GREEN}    [+] Found: $SOURCE_SCRIPT${NC}"

# ── STEP 3: INSTALL DIRECTORY & FILES ─────────────────────────────────────────
echo -e "${YELLOW}[3] Installing to $INSTALL_DIR...${NC}"
mkdir -p "$INSTALL_DIR"
cp "$SOURCE_SCRIPT" "$DEST_SCRIPT"
chmod 755 "$DEST_SCRIPT"
touch "$LOG_FILE"
chmod 644 "$LOG_FILE"
echo -e "${GREEN}    [+] Installed: $DEST_SCRIPT${NC}"
echo -e "${GREEN}    [+] Log file : $LOG_FILE${NC}"

# ── STEP 4: SYSTEMD USER SERVICE ──────────────────────────────────────────────
echo -e "${YELLOW}[4] Creating systemd user service...${NC}"
mkdir -p "$SERVICE_DIR"

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Wazuh Browser History Monitor
Documentation=https://github.com/Ramkumar2545/wazuh-browser-history-monitoring
After=network.target

[Service]
Type=simple
ExecStart=$PYTHON_BIN $DEST_SCRIPT
WorkingDirectory=$INSTALL_DIR
Restart=always
RestartSec=30
StandardOutput=null
StandardError=journal

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable browser-monitor
systemctl --user restart browser-monitor
sleep 2

if systemctl --user is-active --quiet browser-monitor; then
    echo -e "${GREEN}    [+] Service running: browser-monitor${NC}"
else
    echo -e "${YELLOW}    [!] Service may not have started — check: journalctl --user -u browser-monitor -n 30${NC}"
fi

# Enable linger so service persists even without interactive login
if command -v loginctl &>/dev/null; then
    loginctl enable-linger "$USER" 2>/dev/null || true
    echo -e "${GREEN}    [+] loginctl linger enabled for $USER${NC}"
fi

# ── STEP 5: WAZUH OSSEC.CONF ──────────────────────────────────────────────────
echo -e "${YELLOW}[5] Updating Wazuh ossec.conf...${NC}"
MARKER="<!-- BROWSER_MONITOR -->"

if [ -f "$WAZUH_CONF" ]; then
    if ! sudo grep -q "$MARKER" "$WAZUH_CONF" 2>/dev/null; then
        sudo sed -i "s|</ossec_config>|\n  <!-- BROWSER_MONITOR -->\n  <localfile>\n    <location>$LOG_FILE</location>\n    <log_format>syslog</log_format>\n  </localfile>\n</ossec_config>|" "$WAZUH_CONF"
        echo -e "${GREEN}    [+] localfile block added to ossec.conf${NC}"
        sudo systemctl restart wazuh-agent 2>/dev/null || sudo /var/ossec/bin/wazuh-control restart 2>/dev/null || true
        echo -e "${GREEN}    [+] Wazuh agent restarted${NC}"
    else
        echo -e "${GREEN}    [=] localfile block already present — skipping${NC}"
    fi
else
    echo -e "${YELLOW}    [!] ossec.conf not found at $WAZUH_CONF${NC}"
    echo -e "    Manually add inside <ossec_config>:"
    echo -e "      <localfile>"
    echo -e "        <location>$LOG_FILE</location>"
    echo -e "        <log_format>syslog</log_format>"
    echo -e "      </localfile>"
fi

# ── DONE ──────────────────────────────────────────────────────────────────────
echo -e ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  [SUCCESS] Linux Installation Complete!                  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo -e ""
echo "  Service : systemctl --user status browser-monitor"
echo "  Log     : tail -f $LOG_FILE"
echo "  Journal : journalctl --user -u browser-monitor -f"
echo ""
