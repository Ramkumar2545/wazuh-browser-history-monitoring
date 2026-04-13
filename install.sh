#!/bin/bash
# =============================================================================
# Wazuh Browser Monitor - One-Line Bootstrap Installer for Linux / macOS
# Author  : Ram Kumar G (IT Fortress)
# Version : 2.1
# Repo    : https://github.com/Ramkumar2545/wazuh-browser-history-monitoring
#
# USAGE:
#   curl -sSL https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-history-monitoring/main/install.sh | bash
#   wget -qO- https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-history-monitoring/main/install.sh | bash
#
# ENVIRONMENT SUPPORT:
#   - Normal Linux (systemd user session)
#   - Root user (systemd system service)
#   - Docker / LXC / containers (nohup fallback)
#   - macOS (LaunchAgent)
# =============================================================================

# NOTE: Do NOT use set -e here — systemctl --user fails in Docker/LXC
# and would abort the script before ossec.conf is configured.

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
echo -e "${BLUE}║  Wazuh Browser Monitor - One-Line Installer  v2.1       ║${NC}"
echo -e "${BLUE}║  IT Fortress | github.com/Ramkumar2545                 ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo -e ""

OS="$(uname -s)"
echo -e "${GREEN}[*] OS: $OS${NC}"

# Detect if running as root
IS_ROOT=0
[ "$(id -u)" -eq 0 ] && IS_ROOT=1

# Detect if inside a container (Docker / LXC) — no D-Bus user session
IS_CONTAINER=0
if [ -f /.dockerenv ]; then
    IS_CONTAINER=1
elif grep -qE 'docker|lxc|containerd' /proc/1/cgroup 2>/dev/null; then
    IS_CONTAINER=1
elif ! systemctl --user status &>/dev/null 2>&1; then
    IS_CONTAINER=1
fi

if [ "$IS_CONTAINER" -eq 1 ]; then
    echo -e "${YELLOW}[*] Container/no-D-Bus environment detected — will use system service or nohup fallback${NC}"
fi

# ── STEP 1: PYTHON CHECK ──────────────────────────────────────────────────────
echo -e "${YELLOW}[1] Checking Python 3...${NC}"
PYTHON_BIN=""
for py in python3 python3.12 python3.11 python3.10 python3.9 python3.8; do
    if command -v "$py" &>/dev/null; then PYTHON_BIN=$(command -v "$py"); break; fi
done

if [ -z "$PYTHON_BIN" ] && [ "$OS" = "Darwin" ]; then
    for py in /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
        if [ -x "$py" ]; then PYTHON_BIN="$py"; break; fi
    done
fi

if [ -z "$PYTHON_BIN" ]; then
    echo -e "${RED}[-] Python 3 not found.${NC}"
    [ "$OS" = "Linux" ] && echo "    Install: apt install -y python3  or  dnf install -y python3"
    [ "$OS" = "Darwin" ] && echo "    Install: brew install python3"
    exit 1
fi
echo -e "${GREEN}    [+] $($PYTHON_BIN --version 2>&1) at $PYTHON_BIN${NC}"

# ── STEP 2: CREATE DIR ────────────────────────────────────────────────────────
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

# ── STEP 4: PERSISTENCE ───────────────────────────────────────────────────────
echo -e "${YELLOW}[4] Setting up background service...${NC}"

if [ "$OS" = "Linux" ]; then

    # ── PATH A: Root user OR Container → systemd SYSTEM service ──────────────
    if [ "$IS_ROOT" -eq 1 ] || [ "$IS_CONTAINER" -eq 1 ]; then
        SERVICE_FILE="/etc/systemd/system/browser-monitor.service"
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
WantedBy=multi-user.target
EOF
        # Try systemd system (works on real VMs/bare-metal)
        if systemctl daemon-reload 2>/dev/null && systemctl enable browser-monitor 2>/dev/null && systemctl restart browser-monitor 2>/dev/null; then
            sleep 2
            if systemctl is-active --quiet browser-monitor 2>/dev/null; then
                echo -e "${GREEN}    [+] Systemd SYSTEM service running: browser-monitor${NC}"
            else
                echo -e "${YELLOW}    [!] Systemd loaded but service not active — trying nohup fallback${NC}"
                _start_nohup
            fi
        else
            # ── PATH B: Container with no systemd at all → nohup ─────────────
            echo -e "${YELLOW}    [!] Systemd not available (container) — using nohup background process${NC}"
            _start_nohup
        fi

    # ── PATH C: Non-root with working D-Bus → systemd USER service ───────────
    else
        SERVICE_DIR="$HOME/.config/systemd/user"
        mkdir -p "$SERVICE_DIR"
        cat > "$SERVICE_DIR/browser-monitor.service" <<EOF
[Unit]
Description=Wazuh Browser History Monitor
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
        systemctl --user daemon-reload 2>/dev/null
        systemctl --user enable browser-monitor 2>/dev/null || true
        systemctl --user restart browser-monitor 2>/dev/null || true
        sleep 2
        if systemctl --user is-active --quiet browser-monitor 2>/dev/null; then
            echo -e "${GREEN}    [+] Systemd USER service running: browser-monitor${NC}"
        else
            echo -e "${YELLOW}    [!] User service failed — using nohup fallback${NC}"
            _start_nohup
        fi
        loginctl enable-linger "$USER" 2>/dev/null || true
    fi

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

# ── NOHUP FALLBACK FUNCTION ───────────────────────────────────────────────────
_start_nohup() {
    # Kill any existing instance
    pkill -f "browser-history-monitor.py" 2>/dev/null || true
    sleep 1
    nohup "$PYTHON_BIN" "$DEST_SCRIPT" >> "$INSTALL_DIR/error.log" 2>&1 &
    BGPID=$!
    sleep 2
    if kill -0 "$BGPID" 2>/dev/null; then
        echo -e "${GREEN}    [+] Collector running via nohup (PID $BGPID)${NC}"
        echo "$BGPID" > "$INSTALL_DIR/browser-monitor.pid"
        # Write a restart helper script
        cat > "$INSTALL_DIR/restart.sh" <<RESTART
#!/bin/bash
pkill -f browser-history-monitor.py 2>/dev/null || true
sleep 1
nohup $PYTHON_BIN $DEST_SCRIPT >> $INSTALL_DIR/error.log 2>&1 &
echo \$! > $INSTALL_DIR/browser-monitor.pid
echo "[+] Restarted (PID \$!)"  
RESTART
        chmod +x "$INSTALL_DIR/restart.sh"
        echo -e "${YELLOW}    [!] Container mode: add to /etc/rc.local or crontab for persistence:${NC}"
        echo "        @reboot $PYTHON_BIN $DEST_SCRIPT >> $INSTALL_DIR/error.log 2>&1 &"
    else
        echo -e "${RED}    [-] Collector failed to start. Check: $INSTALL_DIR/error.log${NC}"
    fi
}

# ── STEP 5: WAZUH OSSEC.CONF ──────────────────────────────────────────────────
echo -e "${YELLOW}[5] Updating Wazuh ossec.conf...${NC}"
MARKER="<!-- BROWSER_MONITOR -->"

if [ -f "$WAZUH_CONF" ]; then
    if ! grep -q "$MARKER" "$WAZUH_CONF"; then
        if [ "$OS" = "Darwin" ]; then
            sed -i '' "s|</ossec_config>|\n  $MARKER\n  <localfile>\n    <location>$LOG_FILE</location>\n    <log_format>syslog</log_format>\n  </localfile>\n</ossec_config>|" "$WAZUH_CONF"
        else
            sed -i "s|</ossec_config>|\n  $MARKER\n  <localfile>\n    <location>$LOG_FILE</location>\n    <log_format>syslog</log_format>\n  </localfile>\n</ossec_config>|" "$WAZUH_CONF"
        fi
        echo -e "${GREEN}    [+] localfile block added to ossec.conf${NC}"
        if [ "$OS" = "Darwin" ]; then
            /Library/Ossec/bin/wazuh-control restart 2>/dev/null || true
        else
            systemctl restart wazuh-agent 2>/dev/null || /var/ossec/bin/wazuh-control restart 2>/dev/null || true
        fi
        echo -e "${GREEN}    [+] Wazuh agent restarted${NC}"
    else
        echo -e "${GREEN}    [=] ossec.conf already configured — skipping${NC}"
    fi
else
    echo -e "${YELLOW}    [!] ossec.conf not found at $WAZUH_CONF${NC}"
    echo "        Add manually to /var/ossec/etc/ossec.conf:"
    echo "          <localfile>"
    echo "            <location>$LOG_FILE</location>"
    echo "            <log_format>syslog</log_format>"
    echo "          </localfile>"
fi

# ── DONE ──────────────────────────────────────────────────────────────────────
echo -e ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  [SUCCESS] Installation Complete!                        ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo -e ""
echo "  Collector : $DEST_SCRIPT"
echo "  Log file  : $LOG_FILE"
echo ""
echo "  Watch logs    : tail -f $LOG_FILE"
echo "  Restart script: $INSTALL_DIR/restart.sh"
echo ""
echo "  Wazuh Manager — deploy decoder + rules:"
echo "  https://github.com/Ramkumar2545/wazuh-browser-history-monitoring"
echo ""
