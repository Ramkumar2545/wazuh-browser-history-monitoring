#!/bin/bash
# =============================================================================
# Wazuh Browser Monitor - One-Line Bootstrap Installer for Linux / macOS
# Author  : Ram Kumar G (IT Fortress)
# Version : 2.3 (macOS Fix)
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
#   - macOS (LaunchAgent via launchctl bootstrap)
# =============================================================================

# NOTE: Do NOT use set -e — systemctl --user fails in Docker/LXC
# and would abort the script before ossec.conf is configured.

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

REPO_BASE="https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-history-monitoring/main"
COLLECTOR_URL="$REPO_BASE/collector/browser-history-monitor.py"

# FIX v2.3: INSTALL_DIR and LOG_FILE defined per-OS after we know the OS.
# macOS Wazuh agent runs as the logged-in user -> ~/.browser-monitor
# Linux root agent runs as root              -> /root/.browser-monitor
# Linux non-root                              -> ~/.browser-monitor
OS="$(uname -s)"

if [ "$OS" = "Darwin" ]; then
    INSTALL_DIR="$HOME/.browser-monitor"
else
    if [ "$(id -u)" -eq 0 ]; then
        INSTALL_DIR="/root/.browser-monitor"
    else
        INSTALL_DIR="$HOME/.browser-monitor"
    fi
fi

DEST_SCRIPT="$INSTALL_DIR/browser-history-monitor.py"
LOG_FILE="$INSTALL_DIR/browser_history.log"

# FIX v2.3: macOS Wazuh agent installs to /Library/Ossec, not /var/ossec.
# Detect the correct ossec.conf path at runtime.
if [ "$OS" = "Darwin" ]; then
    if [ -f "/Library/Ossec/etc/ossec.conf" ]; then
        WAZUH_CONF="/Library/Ossec/etc/ossec.conf"
    else
        WAZUH_CONF="/var/ossec/etc/ossec.conf"
    fi
else
    WAZUH_CONF="/var/ossec/etc/ossec.conf"
fi

echo -e ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Wazuh Browser Monitor - Installer  v2.3                ║${NC}"
echo -e "${BLUE}║  IT Fortress | github.com/Ramkumar2545                 ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo -e ""

echo -e "${GREEN}[*] OS: $OS${NC}"

# ── DETECT ENVIRONMENT ───────────────────────────────────────────────────────
IS_ROOT=0
[ "$(id -u)" -eq 0 ] && IS_ROOT=1

IS_CONTAINER=0
if [ -f /.dockerenv ]; then
    IS_CONTAINER=1
elif grep -qE 'docker|lxc|containerd' /proc/1/cgroup 2>/dev/null; then
    IS_CONTAINER=1
elif [ "$OS" = "Linux" ] && ! systemctl --user status >/dev/null 2>&1; then
    IS_CONTAINER=1
fi

if [ "$IS_CONTAINER" -eq 1 ]; then
    echo -e "${YELLOW}[*] Container/no-D-Bus env detected — will use systemd system or nohup${NC}"
fi

# ── NOHUP FALLBACK ───────────────────────────────────────────────────────────
_start_nohup() {
    pkill -f "browser-history-monitor.py" 2>/dev/null || true
    sleep 1
    nohup "$PYTHON_BIN" "$DEST_SCRIPT" >> "$INSTALL_DIR/error.log" 2>&1 &
    BGPID=$!
    sleep 2
    if kill -0 "$BGPID" 2>/dev/null; then
        echo -e "${GREEN}    [+] Collector running via nohup (PID $BGPID)${NC}"
        echo "$BGPID" > "$INSTALL_DIR/browser-monitor.pid"
        cat > "$INSTALL_DIR/restart.sh" <<RESTART
#!/bin/bash
pkill -f browser-history-monitor.py 2>/dev/null || true
sleep 1
nohup $PYTHON_BIN $DEST_SCRIPT >> $INSTALL_DIR/error.log 2>&1 &
echo \$! > $INSTALL_DIR/browser-monitor.pid
echo "[+] Restarted (PID \$!)"
RESTART
        chmod +x "$INSTALL_DIR/restart.sh"
        echo -e "${YELLOW}    [!] Add to crontab for persistence across reboots:${NC}"
        echo "        @reboot $PYTHON_BIN $DEST_SCRIPT >> $INSTALL_DIR/error.log 2>&1 &"
    else
        echo -e "${RED}    [-] Collector failed to start. Check: $INSTALL_DIR/error.log${NC}"
    fi
}

# ── STEP 1: PYTHON CHECK ──────────────────────────────────────────────────────
echo -e "${YELLOW}[1] Checking Python 3...${NC}"
PYTHON_BIN=""
for py in python3 python3.12 python3.11 python3.10 python3.9 python3.8; do
    if command -v "$py" &>/dev/null; then PYTHON_BIN=$(command -v "$py"); break; fi
done
if [ -z "$PYTHON_BIN" ] && [ "$OS" = "Darwin" ]; then
    for py in /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
        [ -x "$py" ] && PYTHON_BIN="$py" && break
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
    echo -e "${RED}[-] Neither curl nor wget found.${NC}"; exit 1
fi
FILE_SIZE=$(wc -c < "$DEST_SCRIPT" 2>/dev/null || echo 0)
if [ "$FILE_SIZE" -lt 1000 ]; then
    echo -e "${RED}[-] Download failed ($FILE_SIZE bytes).${NC}"; exit 1
fi
chmod 755 "$DEST_SCRIPT"
echo -e "${GREEN}    [+] Downloaded: $DEST_SCRIPT ($FILE_SIZE bytes)${NC}"

# ── STEP 4: PERSISTENCE ───────────────────────────────────────────────────────
echo -e "${YELLOW}[4] Setting up background service...${NC}"

if [ "$OS" = "Linux" ]; then

    if [ "$IS_ROOT" -eq 1 ] || [ "$IS_CONTAINER" -eq 1 ]; then
        SERVICE_FILE="/etc/systemd/system/browser-monitor.service"
        cat > "$SERVICE_FILE" <<EOF
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
WantedBy=multi-user.target
EOF
        if systemctl daemon-reload 2>/dev/null && \
           systemctl enable browser-monitor 2>/dev/null && \
           systemctl restart browser-monitor 2>/dev/null; then
            sleep 2
            if systemctl is-active --quiet browser-monitor 2>/dev/null; then
                echo -e "${GREEN}    [+] Systemd SYSTEM service running: browser-monitor${NC}"
            else
                echo -e "${YELLOW}    [!] Systemd inactive — nohup fallback${NC}"
                _start_nohup
            fi
        else
            echo -e "${YELLOW}    [!] Systemd unavailable — nohup fallback${NC}"
            _start_nohup
        fi

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
        systemctl --user daemon-reload 2>/dev/null || true
        systemctl --user enable browser-monitor 2>/dev/null || true
        systemctl --user restart browser-monitor 2>/dev/null || true
        sleep 2
        if systemctl --user is-active --quiet browser-monitor 2>/dev/null; then
            echo -e "${GREEN}    [+] Systemd USER service running: browser-monitor${NC}"
        else
            echo -e "${YELLOW}    [!] User service failed — nohup fallback${NC}"
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
    <array><string>$PYTHON_BIN</string><string>$DEST_SCRIPT</string></array>
    <key>WorkingDirectory</key><string>$INSTALL_DIR</string>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>/dev/null</string>
    <key>StandardErrorPath</key><string>$INSTALL_DIR/error.log</string>
</dict>
</plist>
EOF

    # FIX v2.3: macOS 10.15+ deprecates `launchctl load/unload`.
    # Use `launchctl bootstrap / bootout` with the GUI session domain
    # (gui/UID) which is the correct domain for LaunchAgents.
    # Falls back to legacy load for older macOS versions.
    MAC_UID=$(id -u)
    launchctl bootout "gui/$MAC_UID/$LABEL" 2>/dev/null || \
        launchctl unload "$PLIST_FILE" 2>/dev/null || true
    sleep 1

    # FIX v2.3: Show Full Disk Access reminder BEFORE starting the agent
    # so the user can grant it if needed, preventing a silent failure on
    # the first scan attempt for Safari history.
    echo -e ""
    echo -e "${YELLOW}  ┌─────────────────────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}  │  REQUIRED for Safari history monitoring:                │${NC}"
    echo -e "${YELLOW}  │  Grant Full Disk Access to Python / Terminal:           │${NC}"
    echo -e "${YELLOW}  │  System Settings → Privacy & Security →                 │${NC}"
    echo -e "${YELLOW}  │  Full Disk Access → [ + ] → add: $PYTHON_BIN  │${NC}"
    echo -e "${YELLOW}  │  Also add Terminal.app if running interactively.        │${NC}"
    echo -e "${YELLOW}  └─────────────────────────────────────────────────────────┘${NC}"
    echo -e ""

    if launchctl bootstrap "gui/$MAC_UID" "$PLIST_FILE" 2>/dev/null; then
        sleep 2
        if launchctl print "gui/$MAC_UID/$LABEL" 2>/dev/null | grep -q 'state = running'; then
            echo -e "${GREEN}    [+] LaunchAgent running: $LABEL${NC}"
        else
            # Service loaded but not yet running — this is normal before FDA grant
            echo -e "${GREEN}    [+] LaunchAgent loaded: $LABEL${NC}"
            echo -e "${YELLOW}    [!] Collector will start automatically after Full Disk Access is granted.${NC}"
        fi
    else
        # Fallback for older macOS (pre-Catalina)
        launchctl load "$PLIST_FILE" 2>/dev/null
        sleep 2
        if launchctl list | grep -q "$LABEL"; then
            echo -e "${GREEN}    [+] LaunchAgent loaded (legacy): $LABEL${NC}"
        else
            echo -e "${RED}    [-] LaunchAgent failed to load. Check: $INSTALL_DIR/error.log${NC}"
        fi
    fi
fi

# ── STEP 5: WAZUH OSSEC.CONF ──────────────────────────────────────────────────
echo -e "${YELLOW}[5] Updating Wazuh ossec.conf...${NC}"
echo -e "    Config path: $WAZUH_CONF"
MARKER="<!-- BROWSER_MONITOR -->"

if [ -f "$WAZUH_CONF" ]; then
    if ! grep -q "$MARKER" "$WAZUH_CONF"; then
        if [ "$OS" = "Darwin" ]; then
            sed -i '' "s|</ossec_config>|\n  $MARKER\n  <localfile>\n    <location>$LOG_FILE</location>\n    <log_format>syslog</log_format>\n  </localfile>\n</ossec_config>|" "$WAZUH_CONF"
        else
            sed -i "s|</ossec_config>|\n  $MARKER\n  <localfile>\n    <location>$LOG_FILE</location>\n    <log_format>syslog</log_format>\n  </localfile>\n</ossec_config>|" "$WAZUH_CONF"
        fi
        echo -e "${GREEN}    [+] localfile block added to ossec.conf${NC}"
        # FIX v2.3: Use the correct Wazuh restart command for macOS.
        # macOS Wazuh agent binary lives in /Library/Ossec/bin/.
        if [ "$OS" = "Darwin" ]; then
            /Library/Ossec/bin/wazuh-control restart 2>/dev/null && \
                echo -e "${GREEN}    [+] Wazuh agent restarted${NC}" || \
                echo -e "${YELLOW}    [!] Restart manually: sudo /Library/Ossec/bin/wazuh-control restart${NC}"
        else
            systemctl restart wazuh-agent 2>/dev/null || \
                /var/ossec/bin/wazuh-control restart 2>/dev/null || true
            echo -e "${GREEN}    [+] Wazuh agent restarted${NC}"
        fi
    else
        echo -e "${GREEN}    [=] ossec.conf already configured — skipping${NC}"
    fi
else
    echo -e "${YELLOW}    [!] ossec.conf not found at $WAZUH_CONF. Add manually:${NC}"
    echo "      <localfile>"
    echo "        <location>$LOG_FILE</location>"
    echo "        <log_format>syslog</log_format>"
    echo "      </localfile>"
fi

# ── DONE ──────────────────────────────────────────────────────────────────────
echo -e ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  [SUCCESS] Installation Complete! v2.3                  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo -e ""
echo "  Collector : $DEST_SCRIPT"
echo "  Log file  : $LOG_FILE"
echo "  Config    : $WAZUH_CONF"
echo ""
echo "  Watch logs    : tail -f $LOG_FILE"
if [ "$OS" = "Darwin" ]; then
    MAC_UID=$(id -u)
    LABEL="com.ramkumar.browser-monitor"
    echo "  Service status: launchctl print gui/$MAC_UID/$LABEL"
    echo "  Stop service  : launchctl bootout gui/$MAC_UID/$LABEL"
    echo "  Restart       : launchctl bootstrap gui/$MAC_UID $HOME/Library/LaunchAgents/$LABEL.plist"
else
    echo "  Check PID     : cat $INSTALL_DIR/browser-monitor.pid"
    echo "  Restart       : bash $INSTALL_DIR/restart.sh"
fi
echo ""
echo "  Wazuh Manager — deploy decoder + rules:"
echo "  https://github.com/Ramkumar2545/wazuh-browser-history-monitoring"
echo ""
