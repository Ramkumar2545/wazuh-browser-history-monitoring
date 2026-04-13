#!/bin/bash
# =============================================================================
# Wazuh Browser Monitor - One-Line Bootstrap Installer for Linux / macOS
# Author  : Ram Kumar G (IT Fortress)
# Version : 2.0
# Repo    : https://github.com/Ramkumar2545/wazuh-browser-history-monitoring
#
# USAGE:
#   curl -sSL https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-history-monitoring/main/install.sh | bash
#   or
#   wget -qO- https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-history-monitoring/main/install.sh | bash
#
# VT-CLEAN:
#   - Only downloads the Python collector .py from your own repo
#   - No apt/yum installs (Python must be pre-installed)
#   - No sudo required for core setup
# =============================================================================

set -e

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

REPO_BASE="https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-history-monitoring/main"
COLLECTOR_URL="$REPO_BASE/collector/browser-history-monitor.py"
INSTALL_DIR="$HOME/.browser-monitor"
DEST_SCRIPT="$INSTALL_DIR/browser-history-monitor.py"
LOG_FILE="$INSTALL_DIR/browser_history.log"
WAZUH_CONF="/var/ossec/etc/ossec.conf"

echo -e ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Wazuh Browser Monitor - One-Line Installer             ║${NC}"
echo -e "${BLUE}║  IT Fortress | github.com/Ramkumar2545                 ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo -e ""

OS="$(uname -s)"
echo -e "${GREEN}[*] OS: $OS${NC}"

# ── STEP 1: PYTHON CHECK ──────────────────────────────────────────────────────
echo -e "${YELLOW}[1] Checking Python 3...${NC}"
PYTHON_BIN=""
for py in python3 python3.12 python3.11 python3.10 python3.9 python3.8; do
    if command -v "$py" &>/dev/null; then PYTHON_BIN=$(command -v "$py"); break; fi
done

# macOS: also check Homebrew paths
if [ -z "$PYTHON_BIN" ] && [ "$OS" = "Darwin" ]; then
    for py in /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
        if [ -x "$py" ]; then PYTHON_BIN="$py"; break; fi
    done
fi

if [ -z "$PYTHON_BIN" ]; then
    echo -e "${RED}[-] Python 3 not found.${NC}"
    if [ "$OS" = "Linux" ]; then
        echo "    Install: sudo apt install -y python3   (Ubuntu/Debian)"
        echo "    Install: sudo dnf install -y python3   (AlmaLinux/RHEL)"
    elif [ "$OS" = "Darwin" ]; then
        echo "    Install: brew install python3"
    fi
    exit 1
fi
echo -e "${GREEN}    [+] $($PYTHON_BIN --version 2>&1) at $PYTHON_BIN${NC}"

# ── STEP 2: CREATE DIR ───────────────────────────────────────────────────────────
echo -e "${YELLOW}[2] Creating $INSTALL_DIR...${NC}"
mkdir -p "$INSTALL_DIR"
touch "$LOG_FILE"
chmod 644 "$LOG_FILE"
echo -e "${GREEN}    [+] Directory ready${NC}"

# ── STEP 3: DOWNLOAD COLLECTOR ────────────────────────────────────────────────
echo -e "${YELLOW}[3] Downloading collector...${NC}"
echo -e "    URL: $COLLECTOR_URL"

if command -v curl &>/dev/null; then
    curl -sSL -o "$DEST_SCRIPT" "$COLLECTOR_URL"
elif command -v wget &>/dev/null; then
    wget -qO "$DEST_SCRIPT" "$COLLECTOR_URL"
else
    echo -e "${RED}[-] Neither curl nor wget found.${NC}"
    exit 1
fi

FILE_SIZE=$(wc -c < "$DEST_SCRIPT" 2>/dev/null || echo 0)
if [ "$FILE_SIZE" -lt 1000 ]; then
    echo -e "${RED}[-] Download failed or file too small ($FILE_SIZE bytes).${NC}"
    exit 1
fi
chmod 755 "$DEST_SCRIPT"
echo -e "${GREEN}    [+] Downloaded: $DEST_SCRIPT ($FILE_SIZE bytes)${NC}"

# ── STEP 4: PERSISTENCE ───────────────────────────────────────────────────────────
echo -e "${YELLOW}[4] Setting up background service...${NC}"

if [ "$OS" = "Linux" ]; then
    SERVICE_DIR="$HOME/.config/systemd/user"
    SERVICE_FILE="$SERVICE_DIR/browser-monitor.service"
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
    systemctl --user enable browser-monitor 2>/dev/null || true
    systemctl --user restart browser-monitor
    sleep 2
    if systemctl --user is-active --quiet browser-monitor; then
        echo -e "${GREEN}    [+] Systemd service running: browser-monitor${NC}"
    else
        echo -e "${YELLOW}    [!] Check: journalctl --user -u browser-monitor -n 20${NC}"
    fi
    # Enable linger so service persists without interactive login
    loginctl enable-linger "$USER" 2>/dev/null || true

elif [ "$OS" = "Darwin" ]; then
    PLIST_DIR="$HOME/Library/LaunchAgents"
    LABEL="com.ramkumar.browser-monitor"
    PLIST_FILE="$PLIST_DIR/$LABEL.plist"
    mkdir -p "$PLIST_DIR"
    cat > "$PLIST_FILE" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PYTHON_BIN</string>
        <string>$DEST_SCRIPT</string>
    </array>
    <key>WorkingDirectory</key><string>$INSTALL_DIR</string>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>/dev/null</string>
    <key>StandardErrorPath</key><string>$INSTALL_DIR/error.log</string>
</dict>
</plist>
EOF
    launchctl unload "$PLIST_FILE" 2>/dev/null || true
    launchctl load "$PLIST_FILE"
    sleep 2
    if launchctl list | grep -q "$LABEL"; then
        echo -e "${GREEN}    [+] LaunchAgent running: $LABEL${NC}"
    else
        echo -e "${YELLOW}    [!] Grant Full Disk Access to: $PYTHON_BIN${NC}"
        echo "        System Settings → Privacy & Security → Full Disk Access"
    fi
fi

# ── STEP 5: WAZUH OSSEC.CONF ──────────────────────────────────────────────────
echo -e "${YELLOW}[5] Updating Wazuh ossec.conf...${NC}"
MARKER="<!-- BROWSER_MONITOR -->"

if [ -f "$WAZUH_CONF" ]; then
    if ! grep -q "$MARKER" "$WAZUH_CONF"; then
        if [ "$OS" = "Darwin" ]; then
            sed -i '' "s|</ossec_config>|\n  $MARKER\n  <localfile>\n    <location>$LOG_FILE</location>\n    <log_format>syslog</log_format>\n  </localfile>\n</ossec_config>|" "$WAZUH_CONF"
        else
            sudo sed -i "s|</ossec_config>|\n  $MARKER\n  <localfile>\n    <location>$LOG_FILE</location>\n    <log_format>syslog</log_format>\n  </localfile>\n</ossec_config>|" "$WAZUH_CONF"
        fi
        echo -e "${GREEN}    [+] localfile block added${NC}"
        if [ "$OS" = "Darwin" ]; then
            /Library/Ossec/bin/wazuh-control restart 2>/dev/null || true
        else
            sudo systemctl restart wazuh-agent 2>/dev/null || sudo /var/ossec/bin/wazuh-control restart 2>/dev/null || true
        fi
        echo -e "${GREEN}    [+] Wazuh agent restarted${NC}"
    else
        echo -e "${GREEN}    [=] Already configured — skipping${NC}"
    fi
else
    echo -e "${YELLOW}    [!] ossec.conf not found. Add manually:${NC}"
    echo "      <localfile>"
    echo "        <location>$LOG_FILE</location>"
    echo "        <log_format>syslog</log_format>"
    echo "      </localfile>"
fi

# ── DONE ──────────────────────────────────────────────────────────────────────
echo -e ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  [SUCCESS] Full Deployment Complete!                     ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo -e ""
echo "  Collector : $DEST_SCRIPT"
echo "  Log file  : $LOG_FILE"
echo ""
if [ "$OS" = "Linux" ]; then
    echo "  Watch logs : tail -f $LOG_FILE"
    echo "  Service    : systemctl --user status browser-monitor"
elif [ "$OS" = "Darwin" ]; then
    echo "  Watch logs : tail -f $LOG_FILE"
    echo -e "  ${YELLOW}⚠️  Grant Full Disk Access to: $PYTHON_BIN${NC}"
    echo "     System Settings → Privacy & Security → Full Disk Access"
fi
echo ""
echo "  Wazuh Manager — deploy decoder + rules once:"
echo "  https://github.com/Ramkumar2545/wazuh-browser-history-monitoring"
echo ""
