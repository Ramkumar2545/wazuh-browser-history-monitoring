#!/bin/bash
# =============================================================================
# Wazuh Browser Monitor - One-Line Bootstrap Installer for Linux / macOS
# Author  : Ram Kumar G (IT Fortress)
# Version : 2.4 (macOS root-fix)
# Repo    : https://github.com/Ramkumar2545/wazuh-browser-history-monitoring
#
# USAGE (macOS — do NOT prefix with sudo):
#   curl -sSL https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-history-monitoring/main/install.sh | bash
#
# USAGE (Linux root / non-root):
#   curl -sSL https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-history-monitoring/main/install.sh | bash
#   sudo curl -sSL ... | bash
#
# ENVIRONMENT SUPPORT:
#   - Normal Linux (systemd user session)
#   - Root user Linux (systemd system service)
#   - Docker / LXC / containers (nohup fallback)
#   - macOS (LaunchAgent under the real GUI user, even if script runs as root)
# =============================================================================

# NOTE: Do NOT use set -e — systemctl --user fails in Docker/LXC.

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

REPO_BASE="https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-history-monitoring/main"
COLLECTOR_URL="$REPO_BASE/collector/browser-history-monitor.py"

OS="$(uname -s)"
SCRIPT_UID="$(id -u)"

# =============================================================================
# macOS: resolve the REAL console (GUI) user.
#
# When the installer is piped through `sudo bash` or run from a root shell
# (e.g., the Wazuh agent SSH session), $USER and $HOME point to root.
# LaunchAgents MUST be owned and loaded by the GUI user, not root.
# We detect the real user via `who` or `scutil`, then derive their home
# via `dscl`, and run launchctl as that user with `su -l`.
# =============================================================================
if [ "$OS" = "Darwin" ]; then
    # Prefer the console user reported by scutil (most reliable on Sonoma+)
    MAC_REAL_USER=""
    MAC_REAL_USER=$(scutil <<< "show State:/Users/ConsoleUser" 2>/dev/null \
        | awk '/Name :/ && !/loginwindow/ { print $3; exit }')

    # Fallback: first non-root entry from who (covers SSH + Terminal)
    if [ -z "$MAC_REAL_USER" ] || [ "$MAC_REAL_USER" = "root" ]; then
        MAC_REAL_USER=$(who 2>/dev/null | awk '!/root/ {print $1; exit}')
    fi

    # Last resort: current user if not root
    if [ -z "$MAC_REAL_USER" ] && [ "$SCRIPT_UID" -ne 0 ]; then
        MAC_REAL_USER="$USER"
    fi

    if [ -z "$MAC_REAL_USER" ] || [ "$MAC_REAL_USER" = "root" ]; then
        echo -e "${RED}[!] macOS: Cannot determine the real GUI user.${NC}"
        echo -e "${YELLOW}    Run the installer WITHOUT sudo as your normal user:${NC}"
        echo "    curl -sSL https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-history-monitoring/main/install.sh | bash"
        exit 1
    fi

    # Resolve home directory and UID of the real user
    MAC_REAL_HOME=$(dscl . -read "/Users/$MAC_REAL_USER" NFSHomeDirectory 2>/dev/null \
        | awk '{print $2}')
    [ -z "$MAC_REAL_HOME" ] && MAC_REAL_HOME="/Users/$MAC_REAL_USER"
    MAC_REAL_UID=$(id -u "$MAC_REAL_USER" 2>/dev/null)

    # Override HOME and INSTALL_DIR to the real user
    REAL_HOME="$MAC_REAL_HOME"
    INSTALL_DIR="$REAL_HOME/.browser-monitor"

    echo -e "${GREEN}[*] macOS real user : $MAC_REAL_USER (uid=$MAC_REAL_UID)${NC}"
    echo -e "${GREEN}[*] Real home       : $REAL_HOME${NC}"
else
    REAL_HOME="$HOME"
    if [ "$SCRIPT_UID" -eq 0 ]; then
        INSTALL_DIR="/root/.browser-monitor"
    else
        INSTALL_DIR="$HOME/.browser-monitor"
    fi
fi

DEST_SCRIPT="$INSTALL_DIR/browser-history-monitor.py"
LOG_FILE="$INSTALL_DIR/browser_history.log"

# Detect ossec.conf path
if [ "$OS" = "Darwin" ]; then
    if   [ -f "/Library/Ossec/etc/ossec.conf" ]; then
        WAZUH_CONF="/Library/Ossec/etc/ossec.conf"
    else
        WAZUH_CONF="/var/ossec/etc/ossec.conf"
    fi
else
    WAZUH_CONF="/var/ossec/etc/ossec.conf"
fi

echo -e ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Wazuh Browser Monitor - Installer  v2.4                ║${NC}"
echo -e "${BLUE}║  IT Fortress | github.com/Ramkumar2545                 ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo -e ""
echo -e "${GREEN}[*] OS: $OS${NC}"

# ── DETECT ENVIRONMENT ───────────────────────────────────────────────────────
IS_ROOT=0
[ "$SCRIPT_UID" -eq 0 ] && IS_ROOT=1

IS_CONTAINER=0
if [ -f /.dockerenv ]; then
    IS_CONTAINER=1
elif grep -qE 'docker|lxc|containerd' /proc/1/cgroup 2>/dev/null; then
    IS_CONTAINER=1
elif [ "$OS" = "Linux" ] && ! systemctl --user status >/dev/null 2>&1; then
    IS_CONTAINER=1
fi

[ "$IS_CONTAINER" -eq 1 ] && \
    echo -e "${YELLOW}[*] Container/no-D-Bus env detected — will use systemd system or nohup${NC}"

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
        echo -e "${YELLOW}    [!] Add to crontab for persistence:${NC}"
        echo "        @reboot $PYTHON_BIN $DEST_SCRIPT >> $INSTALL_DIR/error.log 2>&1 &"
    else
        echo -e "${RED}    [-] Collector failed to start. Check: $INSTALL_DIR/error.log${NC}"
    fi
}

# ── STEP 1: PYTHON CHECK ──────────────────────────────────────────────────────
echo -e "${YELLOW}[1] Checking Python 3...${NC}"
PYTHON_BIN=""
for py in python3 python3.13 python3.12 python3.11 python3.10 python3.9 python3.8; do
    if command -v "$py" &>/dev/null; then PYTHON_BIN=$(command -v "$py"); break; fi
done
if [ -z "$PYTHON_BIN" ] && [ "$OS" = "Darwin" ]; then
    for py in /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
        [ -x "$py" ] && PYTHON_BIN="$py" && break
    done
fi
if [ -z "$PYTHON_BIN" ]; then
    echo -e "${RED}[-] Python 3 not found.${NC}"
    [ "$OS" = "Linux" ]  && echo "    Install: apt install -y python3  or  dnf install -y python3"
    [ "$OS" = "Darwin" ] && echo "    Install: brew install python3"
    exit 1
fi
echo -e "${GREEN}    [+] $($PYTHON_BIN --version 2>&1) at $PYTHON_BIN${NC}"

# ── STEP 2: CREATE DIRS ──────────────────────────────────────────────────────
echo -e "${YELLOW}[2] Creating $INSTALL_DIR...${NC}"
mkdir -p "$INSTALL_DIR"
touch "$LOG_FILE"
chmod 644 "$LOG_FILE"
# On macOS, if running as root, fix ownership so real user can write
if [ "$OS" = "Darwin" ] && [ "$IS_ROOT" -eq 1 ]; then
    chown -R "$MAC_REAL_USER" "$INSTALL_DIR"
fi
echo -e "${GREEN}    [+] Directory ready${NC}"

# ── STEP 3: DOWNLOAD COLLECTOR ───────────────────────────────────────────────
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
[ "$OS" = "Darwin" ] && [ "$IS_ROOT" -eq 1 ] && chown "$MAC_REAL_USER" "$DEST_SCRIPT"
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
            systemctl is-active --quiet browser-monitor 2>/dev/null && \
                echo -e "${GREEN}    [+] Systemd SYSTEM service running: browser-monitor${NC}" || \
                { echo -e "${YELLOW}    [!] Systemd inactive — nohup fallback${NC}"; _start_nohup; }
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
        systemctl --user enable  browser-monitor 2>/dev/null || true
        systemctl --user restart browser-monitor 2>/dev/null || true
        sleep 2
        systemctl --user is-active --quiet browser-monitor 2>/dev/null && \
            echo -e "${GREEN}    [+] Systemd USER service running: browser-monitor${NC}" || \
            { echo -e "${YELLOW}    [!] User service failed — nohup fallback${NC}"; _start_nohup; }
        loginctl enable-linger "$USER" 2>/dev/null || true
    fi

elif [ "$OS" = "Darwin" ]; then

    LABEL="com.ramkumar.browser-monitor"
    # ALWAYS write the plist into the REAL user's LaunchAgents, never root's
    PLIST_DIR="$REAL_HOME/Library/LaunchAgents"
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
    <key>UserName</key><string>$MAC_REAL_USER</string>
</dict>
</plist>
EOF
    # Ensure plist is owned by the real user, never root
    chown "$MAC_REAL_USER" "$PLIST_FILE"
    chmod 644 "$PLIST_FILE"

    # Full Disk Access reminder BEFORE loading
    echo -e ""
    echo -e "${YELLOW}  ┌─────────────────────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}  │  REQUIRED for Safari history monitoring:             │${NC}"
    echo -e "${YELLOW}  │  System Settings → Privacy & Security →              │${NC}"
    echo -e "${YELLOW}  │  Full Disk Access → [ + ] → add:                     │${NC}"
    echo -e "${YELLOW}  │    • $PYTHON_BIN${NC}"
    echo -e "${YELLOW}  │    • Terminal.app (if running interactively)          │${NC}"
    echo -e "${YELLOW}  └─────────────────────────────────────────────────────────┘${NC}"
    echo -e ""

    # Unload any existing instance first, running AS the real user
    if [ "$IS_ROOT" -eq 1 ]; then
        su -l "$MAC_REAL_USER" -c \
            "launchctl bootout gui/$MAC_REAL_UID/$LABEL 2>/dev/null; true" 2>/dev/null || true
    else
        launchctl bootout "gui/$MAC_REAL_UID/$LABEL" 2>/dev/null || true
    fi
    sleep 1

    # Load the LaunchAgent AS the real GUI user
    LOAD_OK=0
    if [ "$IS_ROOT" -eq 1 ]; then
        su -l "$MAC_REAL_USER" -c \
            "launchctl bootstrap gui/$MAC_REAL_UID '$PLIST_FILE'" 2>/dev/null && LOAD_OK=1
    else
        launchctl bootstrap "gui/$MAC_REAL_UID" "$PLIST_FILE" 2>/dev/null && LOAD_OK=1
    fi

    # Legacy fallback (pre-Catalina)
    if [ "$LOAD_OK" -eq 0 ]; then
        if [ "$IS_ROOT" -eq 1 ]; then
            su -l "$MAC_REAL_USER" -c \
                "launchctl load '$PLIST_FILE'" 2>/dev/null && LOAD_OK=1
        else
            launchctl load "$PLIST_FILE" 2>/dev/null && LOAD_OK=1
        fi
    fi

    sleep 2
    if [ "$LOAD_OK" -eq 1 ]; then
        echo -e "${GREEN}    [+] LaunchAgent loaded for user: $MAC_REAL_USER${NC}"
        echo -e "${GREEN}    [+] Label: $LABEL${NC}"
        echo -e "${YELLOW}    [!] Collector starts automatically at login and on reboot.${NC}"
    else
        echo -e "${RED}    [-] LaunchAgent failed to load.${NC}"
        echo -e "${YELLOW}    Run manually as $MAC_REAL_USER:${NC}"
        echo "        launchctl bootstrap gui/$MAC_REAL_UID $PLIST_FILE"
    fi
fi

# ── STEP 5: WAZUH OSSEC.CONF ─────────────────────────────────────────────────
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
echo -e "${GREEN}║  [SUCCESS] Installation Complete! v2.4                  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo -e ""
echo "  Collector : $DEST_SCRIPT"
echo "  Log file  : $LOG_FILE"
echo "  Config    : $WAZUH_CONF"
echo ""
echo "  Watch logs : tail -f $LOG_FILE"
if [ "$OS" = "Darwin" ]; then
    echo "  Status     : launchctl print gui/$MAC_REAL_UID/$LABEL"
    echo "  Stop       : launchctl bootout gui/$MAC_REAL_UID/$LABEL"
    echo "  Restart    : launchctl bootstrap gui/$MAC_REAL_UID $PLIST_FILE"
else
    echo "  Check PID  : cat $INSTALL_DIR/browser-monitor.pid"
    echo "  Restart    : bash $INSTALL_DIR/restart.sh"
fi
echo ""
echo "  Wazuh Manager — deploy decoder + rules:"
echo "  https://github.com/Ramkumar2545/wazuh-browser-history-monitoring"
echo ""
