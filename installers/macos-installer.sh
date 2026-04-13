#!/bin/bash
# =============================================================================
# Wazuh Browser Monitor - macOS Installer
# Author  : Ram Kumar G (IT Fortress)
# Version : 2.0
# Supports: macOS 12 Monterey, 13 Ventura, 14 Sonoma, 15 Sequoia
#
# VT-CLEAN: No internet downloads, no remote script fetching.
# Run as the user to monitor (no sudo needed for core setup).
# =============================================================================

set -e

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

REPO_ROOT="$(dirname "$(dirname "$(realpath "$0")")")" 
SOURCE_SCRIPT="$REPO_ROOT/collector/browser-history-monitor.py"
INSTALL_DIR="$HOME/.browser-monitor"
DEST_SCRIPT="$INSTALL_DIR/browser-history-monitor.py"
LOG_FILE="$INSTALL_DIR/browser_history.log"
PLIST_DIR="$HOME/Library/LaunchAgents"
LABEL="com.ramkumar.browser-monitor"
PLIST_FILE="$PLIST_DIR/$LABEL.plist"
WAZUH_CONF="/Library/Ossec/etc/ossec.conf"

echo -e ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Wazuh Browser Monitor - macOS Installer                 ║${NC}"
echo -e "${BLUE}║  IT Fortress | VT-Clean | No Internet Downloads          ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo -e ""

macOS_VER=$(sw_vers -productVersion)
echo -e "${GREEN}[*] macOS $macOS_VER${NC}"

# ── STEP 1: PYTHON CHECK ──────────────────────────────────────────────────────
echo -e "${YELLOW}[1] Checking Python 3...${NC}"
PYTHON_BIN=""
for py in /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3 $(which python3 2>/dev/null); do
    if [ -x "$py" ]; then PYTHON_BIN="$py"; break; fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo -e "${RED}[-] Python 3 not found.${NC}"
    echo "    Install via Homebrew: brew install python3"
    echo "    Or download from:     https://python.org"
    exit 1
fi
echo -e "${GREEN}    [+] $($PYTHON_BIN --version 2>&1) at $PYTHON_BIN${NC}"

# ── STEP 2: VERIFY SOURCE SCRIPT ──────────────────────────────────────────────
echo -e "${YELLOW}[2] Verifying collector script...${NC}"
if [ ! -f "$SOURCE_SCRIPT" ]; then
    echo -e "${RED}[-] Collector not found at: $SOURCE_SCRIPT${NC}"
    echo "    Clone the full repo first."
    exit 1
fi
echo -e "${GREEN}    [+] Found: $SOURCE_SCRIPT${NC}"

# ── STEP 3: INSTALL FILES ─────────────────────────────────────────────────────
echo -e "${YELLOW}[3] Installing to $INSTALL_DIR...${NC}"
mkdir -p "$INSTALL_DIR"
cp "$SOURCE_SCRIPT" "$DEST_SCRIPT"
chmod 755 "$DEST_SCRIPT"
touch "$LOG_FILE"
chmod 644 "$LOG_FILE"
echo -e "${GREEN}    [+] Installed: $DEST_SCRIPT${NC}"
echo -e "${GREEN}    [+] Log file : $LOG_FILE${NC}"

# ── STEP 4: LAUNCHAGENT PLIST ─────────────────────────────────────────────────
echo -e "${YELLOW}[4] Creating LaunchAgent...${NC}"
mkdir -p "$PLIST_DIR"

cat > "$PLIST_FILE" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PYTHON_BIN</string>
        <string>$DEST_SCRIPT</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$INSTALL_DIR</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
    <key>StandardErrorPath</key>
    <string>$INSTALL_DIR/error.log</string>
</dict>
</plist>
EOF

launchctl unload "$PLIST_FILE" 2>/dev/null || true
launchctl load "$PLIST_FILE"
sleep 2

if launchctl list | grep -q "$LABEL"; then
    echo -e "${GREEN}    [+] LaunchAgent running: $LABEL${NC}"
else
    echo -e "${YELLOW}    [!] LaunchAgent may not have started.${NC}"
    echo "        Grant Full Disk Access first (see Step 4.4 in README)"
    echo "        Then reload:"
    echo "          launchctl unload $PLIST_FILE"
    echo "          launchctl load $PLIST_FILE"
fi

# ── STEP 5: WAZUH OSSEC.CONF ──────────────────────────────────────────────────
echo -e "${YELLOW}[5] Updating Wazuh ossec.conf...${NC}"
MARKER="<!-- BROWSER_MONITOR -->"

if [ -f "$WAZUH_CONF" ]; then
    if ! grep -q "$MARKER" "$WAZUH_CONF"; then
        # macOS sed requires '' for in-place edit
        sed -i '' "s|</ossec_config>|\n  <!-- BROWSER_MONITOR -->\n  <localfile>\n    <location>$LOG_FILE</location>\n    <log_format>syslog</log_format>\n  </localfile>\n</ossec_config>|" "$WAZUH_CONF"
        echo -e "${GREEN}    [+] localfile block added to ossec.conf${NC}"
        /Library/Ossec/bin/wazuh-control restart 2>/dev/null || true
        echo -e "${GREEN}    [+] Wazuh agent restarted${NC}"
    else
        echo -e "${GREEN}    [=] localfile block already present — skipping${NC}"
    fi
else
    echo -e "${YELLOW}    [!] ossec.conf not found at $WAZUH_CONF${NC}"
    echo "    Add manually inside <ossec_config>:"
    echo "      <localfile>"
    echo "        <location>$LOG_FILE</location>"
    echo "        <log_format>syslog</log_format>"
    echo "      </localfile>"
fi

# ── DONE ──────────────────────────────────────────────────────────────────────
echo -e ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  [SUCCESS] macOS Installation Complete!                  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo -e ""
echo "  Service : launchctl list | grep browser-monitor"
echo "  Log     : tail -f $LOG_FILE"
echo "  Errors  : tail -f $INSTALL_DIR/error.log"
echo ""
echo -e "${YELLOW}  ⚠️  IMPORTANT: Grant Full Disk Access to Python:${NC}"
echo "     System Settings → Privacy & Security → Full Disk Access"
echo "     Add: $PYTHON_BIN"
echo "     Then reload: launchctl unload $PLIST_FILE"
echo "                  launchctl load $PLIST_FILE"
echo ""
