# 🌐 Wazuh Browser History Monitoring

> **Real-time browser history monitoring** integrated with **Wazuh SIEM** — monitor Chrome, Edge, Brave, Firefox (incl. Snap/Flatpak), Opera, Vivaldi, Waterfox, Tor, and Safari across **Windows, Linux, and macOS** endpoints with security alerts on the Wazuh Dashboard.

[![Wazuh](https://img.shields.io/badge/Wazuh-4.x-blue?style=flat-square)](https://wazuh.com)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)](#)
[![Python](https://img.shields.io/badge/Python-3.8%2B-green?style=flat-square)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![Author](https://img.shields.io/badge/Author-Ram%20Kumar%20G-orange?style=flat-square)](https://github.com/Ramkumar2545)
[![VT-Clean](https://img.shields.io/badge/VirusTotal-Clean-brightgreen?style=flat-square)](#)

---

## 📋 Table of Contents

- [Architecture](#architecture)
- [Supported Browsers](#supported-browsers)
- [Prerequisites](#prerequisites)
- [⚙️ PHASE 1 — Wazuh Manager Setup](#️-phase-1--wazuh-manager-setup-do-this-once-on-the-manager)
  - [1.1 Deploy Decoder](#11--deploy-the-decoder)
  - [1.2 Deploy Rules](#12--deploy-the-rules)
  - [1.3 Update ossec.conf (Manager)](#13--update-ossecconf-on-manager-optional--centralised-log-pull)
  - [1.4 Validate & Restart](#14--validate--restart-manager)
  - [1.5 Test with wazuh-logtest](#15--test-with-wazuh-logtest)
- [🚀 PHASE 2 — Endpoint Deploy](#-phase-2--endpoint-deploy)
  - [Windows](#-windows-endpoint)
  - [Linux](#-linux-endpoint)
  - [macOS](#-macos-endpoint)
- [Step 5 — Verify in Dashboard](#step-5--verify-in-dashboard)
- [Detection Rules Reference](#detection-rules-reference)
- [Troubleshooting](#troubleshooting)
- [Repo Structure](#repo-structure)

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                   WAZUH MANAGER                      │
│  ┌──────────────────────┐  ┌────────────────────────┐│
│  │ Decoder               │─▶│ Rules (900100–900122)  ││
│  │ 0310-browser_history  │  │ Alerts → Dashboard     ││
│  └──────────────────────┘  └────────────────────────┘│
└───────────────────────────────┬──────────────────────┘
                                │  Wazuh Agent (enrolled)
          ┌─────────────────────┼─────────────────────┐
          ▼                     ▼                     ▼
   Windows Endpoint       Linux Endpoint       macOS Endpoint
  (Scheduled Task)     (systemd SYSTEM svc)  (LaunchAgent)
          │                     │                     │
   browser-history-monitor.py  ←  reads SQLite DBs every 60s
          │
   writes → browser_history.log
          │
   <localfile> in ossec.conf  →  Wazuh Agent  →  Manager
```

**Flow:**
1. Collector reads browser SQLite DBs every 60 seconds (all users, all install types)
2. Writes new visits as syslog-format lines to a log file
3. Wazuh agent ships the log file to the manager
4. Decoder parses fields (`browser`, `url`, `profile`, `username`, `hostname`)
5. Rules fire alerts based on URL patterns & risk categories
6. Alerts appear in Wazuh Dashboard with MITRE ATT&CK mapping

---

## Supported Browsers

| Browser | Windows | Linux (Standard) | Linux (Snap) | Linux (Flatpak) | macOS |
|---|---|---|---|---|---|
| Google Chrome | ✅ | ✅ | ✅ | ✅ | ✅ |
| Microsoft Edge | ✅ | ✅ | ✅ | ✅ | ✅ |
| Brave | ✅ | ✅ | ✅ | ✅ | ✅ |
| Firefox | ✅ | ✅ | ✅ | ✅ | ✅ |
| Opera / Opera GX | ✅ | ✅ | ✅ | ✅ | ✅ |
| Vivaldi | ✅ | ✅ | ✅ | ✅ | ✅ |
| Chromium | ❌ | ✅ | ✅ | ✅ | ❌ |
| Waterfox | ✅ | ✅ | ❌ | ✅ | ✅ |
| Tor Browser | ✅ | ✅ | ❌ | ✅ | ❌ |
| Safari | ❌ | ❌ | ❌ | ❌ | ✅ |

> ✅ The collector auto-detects all install types — no configuration needed.

---

## Prerequisites

| Component | Requirement |
|---|---|
| Wazuh Manager | v4.x |
| Wazuh Agent | Installed & enrolled on each endpoint |
| Windows | Windows 10/11 / Server 2016+, Python 3.8+ (system-wide) |
| Linux | Ubuntu 20.04+, Debian 11+, AlmaLinux 8+, RHEL 8+, Python 3.8+ |
| macOS | macOS 12+ (Monterey+), Python 3.8+ |

> ⚠️ **Python must be installed system-wide on Windows** — check "Install for All Users" and "Add to PATH" during setup.

---

## ⚙️ PHASE 1 — Wazuh Manager Setup *(Do this ONCE on the Manager)*

> 🖥️ These steps run **only on your Wazuh Manager server** and enable detection for ALL enrolled endpoints automatically.

### 1.1 — Deploy the Decoder

The decoder teaches Wazuh how to parse browser history log lines into structured fields.

```bash
# Clone the repo
cd /tmp
git clone https://github.com/Ramkumar2545/wazuh-browser-history-monitoring.git
cd wazuh-browser-history-monitoring

# Copy decoder
sudo cp wazuh/decoders/0310-browser_history_decoder.xml /var/ossec/etc/decoders/
sudo chown wazuh:wazuh /var/ossec/etc/decoders/0310-browser_history_decoder.xml
sudo chmod 660 /var/ossec/etc/decoders/0310-browser_history_decoder.xml

# Verify
ls -lah /var/ossec/etc/decoders/0310-browser_history_decoder.xml
```

---

### 1.2 — Deploy the Rules

```bash
# Copy rules
sudo cp wazuh/rules/0310-browser_history_rules.xml /var/ossec/etc/rules/
sudo chown wazuh:wazuh /var/ossec/etc/rules/0310-browser_history_rules.xml
sudo chmod 660 /var/ossec/etc/rules/0310-browser_history_rules.xml

# Verify
ls -lah /var/ossec/etc/rules/0310-browser_history_rules.xml
```

**Rules summary:**

| Rule ID | Level | Category | Example Match |
|---|---|---|---|
| 900100 | 3 | Baseline visibility | Any browser visit |
| 900101 | 10 | Dangerous download | `.exe` `.ps1` `.hta` `.msi` `.iso` `.bat` `.vbs` `.dll` in URL |
| 900102 | 10 | Phishing / Credential | `login` `mfa` `verify` `otp` `2fa` `password-reset` in URL |
| 900103 | 8 | Anonymizer / TOR | `torproject.org`, `protonvpn`, `nordvpn`, `expressvpn` |
| 900104 | 7 | Data exfiltration | `pastebin.com`, `mega.nz`, `wetransfer`, `gofile.io` |
| 900105 | 6 | Cloud storage upload | `drive.google.com`, `onedrive`, `dropbox`, `pcloud` |
| 900106 | 4 | Non-HTTP scheme | `ftp://`, `file://`, `data:`, `blob:`, `javascript:` |
| 900107 | 3 | Insecure HTTP | URL starts with `http://` (not https, excludes LAN) |
| 900108 | 5 | Crypto / Trading | `binance.com`, `coinbase.com`, `metamask.io`, `opensea.io` |
| 900109 | 3 | Social Media | `facebook`, `x.com`, `instagram`, `tiktok`, `discord` |
| 900110 | 9 | Exploit / Hacking tool | `exploit-db.com`, `shodan.io`, `censys.io`, `nulled.to` |
| 900111 | 9 | Dark web / .onion proxy | `.onion`, `dark.fail`, `ahmia.fi`, `onion.to` |
| 900112 | 8 | Malware keyword in URL | `malware`, `ransomware`, `botnet`, `trojan`, `dropper` |
| 900113 | 3 | Service lifecycle | Collector startup / shutdown message |
| 900114 | 3 | Background / Redirect | No Title entries — background requests suppressed |
| 900115 | 3 | Gaming sites | `steam`, `epicgames`, `xbox`, `roblox`, `twitch` |
| 900116 | 3 | Streaming / Entertainment | `youtube`, `netflix`, `spotify`, `hotstar`, `disneyplus` |
| 900117 | 3 | AI / GenAI platforms | `chatgpt`, `claude.ai`, `gemini`, `perplexity.ai` |
| 900118 | 3 | Shopping / E-commerce | `amazon`, `flipkart`, `ebay`, `aliexpress`, `myntra` |
| 900119 | 3 | News / Media | `bbc`, `cnn`, `ndtv`, `thehindu`, `thehackernews` |
| 900120 | 3 | Developer / DevOps tools | `github`, `gitlab`, `stackoverflow`, `docker`, `pypi` |
| 900121 | 10 | Adult / Inappropriate content | Explicit site domains |
| 900122 | 3 | Catch-all general visit | Any `https://` URL not matched by rules above |

---

### 1.3 — Update `ossec.conf` on Manager *(Optional — Centralised Config)*

> Only needed if you use **agent groups** for centralised config. Otherwise the agent's `ossec.conf` is patched automatically in Phase 2.

```bash
sudo nano /var/ossec/etc/shared/default/agent.conf
```

Add inside `<agent_config>`:

```xml
<!-- Browser Monitor: Windows -->
<agent_config os="Windows">
  <localfile>
    <location>C:\BrowserMonitor\browser_history.log</location>
    <log_format>syslog</log_format>
  </localfile>
</agent_config>

<!-- Browser Monitor: Linux -->
<agent_config os="Linux">
  <localfile>
    <location>/root/.browser-monitor/browser_history.log</location>
    <log_format>syslog</log_format>
  </localfile>
</agent_config>

<!-- Browser Monitor: macOS -->
<agent_config os="Darwin">
  <localfile>
    <location>/root/.browser-monitor/browser_history.log</location>
    <log_format>syslog</log_format>
  </localfile>
</agent_config>
```

---

### 1.4 — Validate & Restart Manager

```bash
# Validate — should output no ERROR or CRITICAL lines
sudo /var/ossec/bin/wazuh-analysisd -t

# Restart
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
```

---

### 1.5 — Test with `wazuh-logtest`

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste this test line:
```
Apr 13 22:41:00 agent browser-monitor: 2026-04-13 22:41:00 Chrome agent Default https://pastebin.com/xyz Pastebin
```

Expected output:
```
**Phase 1: Completed pre-decoding.
    program_name: 'browser-monitor'

**Phase 2: Completed decoding.
    name: 'browser-monitor-log-fields'
    mon_browse_time: '2026-04-13 22:41:00'
    mon_browser_name: 'Chrome'
    mon_browser_profile: 'Default'
    mon_url: 'https://pastebin.com/xyz'
    mon_page_title: 'Pastebin'

**Phase 3: Completed filtering (rules).
    id: '900104'
    level: '7'
    description: 'Browser Data-Sharing Site visited'
```

✅ **Phase 1 complete — Manager is ready.**

---

---

## 🚀 PHASE 2 — Endpoint Deploy

> Run these steps **on each endpoint** you want to monitor.  
> The installer handles everything: service creation, ossec.conf patching, and agent restart.

---

### 🪟 Windows Endpoint

#### Step 1 — Install Python (if not already installed)

1. Download from [https://python.org/downloads](https://python.org/downloads)
2. During install, check **both**:
   - ✅ Install for All Users
   - ✅ Add Python to PATH
3. Verify: open PowerShell and run `python --version`

#### Step 2 — Run Installer

Open **PowerShell as Administrator**:

```powershell
powershell -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; iwr -UseBasicParsing 'https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-history-monitoring/main/install.ps1' | iex"
```

**The installer automatically:**
- Downloads `browser-history-monitor.py` to `C:\BrowserMonitor\`
- Creates a **Scheduled Task** (`BrowserHistoryMonitor`) that runs at every user logon
- Adds a `<localfile>` block to `C:\Program Files (x86)\ossec-agent\ossec.conf`
- Restarts the Wazuh agent service
- Starts monitoring immediately

#### Step 3 — Verify Installation

```powershell
# Check collector is writing logs
Get-Content 'C:\BrowserMonitor\browser_history.log' -Tail 20 -Wait

# Check scheduled task status
Get-ScheduledTask -TaskName 'BrowserHistoryMonitor' | Select-Object TaskName, State

# Check Wazuh agent
Get-Service WazuhSvc

# Check ossec.conf was patched
Select-String 'BrowserMonitor' 'C:\Program Files (x86)\ossec-agent\ossec.conf'
```

#### Step 4 — Verify Browser Profiles are Detected

Run these in PowerShell to confirm the collector can find browser history databases:

```powershell
# Find ALL Chrome/Edge/Brave History SQLite files
Get-ChildItem -Path "$env:LOCALAPPDATA" -Recurse -Filter "History" -ErrorAction SilentlyContinue `
  | Where-Object { $_.DirectoryName -match 'Chrome|Edge|Brave|Vivaldi|Opera' } `
  | Select-Object FullName

# Find ALL Firefox places.sqlite files
Get-ChildItem -Path "$env:APPDATA\Mozilla\Firefox\Profiles" -Recurse -Filter "places.sqlite" -ErrorAction SilentlyContinue `
  | Select-Object FullName

# Check which user is logged in and running browsers
Get-Process -Name 'chrome','msedge','brave','firefox','opera','vivaldi' -ErrorAction SilentlyContinue `
  | Select-Object Name, Id, @{N='User';E={(Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").GetOwner().User}}

# Confirm collector process is running
Get-Process -Name python* -ErrorAction SilentlyContinue | Select-Object Id, Name, Path

# Check current Windows username
$env:USERNAME
```

**What to look for:**
- If `History` or `places.sqlite` files appear → collector will detect them within 60 seconds
- If nothing appears → browser has never been opened; open it and browse once, then re-check

#### Step 5 — Expected Log Format

```
Apr 13 11:00:01 WIN-PC browser-monitor: 2026-04-13 11:00:01 Chrome JohnDoe Default https://google.com Google
```

Fields: `timestamp browser username profile url title`

#### Step 6 — Manual ossec.conf Patch (if not auto-applied)

Edit `C:\Program Files (x86)\ossec-agent\ossec.conf` and add before `</ossec_config>`:

```xml
<localfile>
  <location>C:\BrowserMonitor\browser_history.log</location>
  <log_format>syslog</log_format>
</localfile>
```

Then restart the agent:
```powershell
Restart-Service WazuhSvc
```

#### Uninstall

```powershell
Unregister-ScheduledTask -TaskName 'BrowserHistoryMonitor' -Confirm:$false
Remove-Item 'C:\BrowserMonitor' -Recurse -Force
```

---

### 🐧 Linux Endpoint

> **Important:** The collector runs as **root** (via systemd SYSTEM service) so it can read browser profiles from all users on the machine — including snap/flatpak installs.

#### Step 1 — Run Installer

```bash
curl -sSL https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-history-monitoring/main/install.sh | bash
```

Or with wget:
```bash
wget -qO- https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-history-monitoring/main/install.sh | bash
```

**The installer automatically:**
- Detects Python 3 at `/usr/bin/python3`
- Downloads `browser-history-monitor.py` to `/root/.browser-monitor/`
- Creates a **systemd SYSTEM service** (`browser-monitor`) at `/etc/systemd/system/browser-monitor.service`
- Adds a `<localfile>` block to `/var/ossec/etc/ossec.conf`
- Restarts the Wazuh agent
- Starts monitoring immediately

#### Step 2 — Verify Installation

```bash
# Check service status (SYSTEM service — do NOT use --user)
systemctl status browser-monitor

# Check service logs
journalctl -u browser-monitor -n 20 --no-pager

# Watch live browser history log
tail -f /root/.browser-monitor/browser_history.log

# Confirm ossec.conf was patched
grep -A3 'browser' /var/ossec/etc/ossec.conf

# Check Wazuh agent is running
systemctl status wazuh-agent
```

#### Step 3 — Verify Browser Profiles are Detected

Run these to confirm the collector can find browser history databases on your system:

```bash
# Find ALL Firefox places.sqlite files across the entire system
find / -name "places.sqlite" 2>/dev/null

# Find ALL Firefox profile directories (standard + snap + flatpak)
find / -name "*.default*" -path "*/firefox/*" -type d 2>/dev/null

# Find ALL Chrome/Edge/Brave/Chromium History SQLite files
find / -name "History" -path "*/Default/*" 2>/dev/null
find / -name "History" -path "*/Profile*/*" 2>/dev/null

# Check which user is running the browser
ps aux | grep -iE 'firefox|chrome|brave|edge|chromium|opera|vivaldi'

# Check all user home directories on this machine
cat /etc/passwd | grep -v nologin | grep -v false | awk -F: '{print $1, $6}'

# Confirm collector process is running
ps aux | grep browser-history
```

**What to look for:**

| Output | Meaning |
|---|---|
| `places.sqlite` paths appear | ✅ Firefox detected — collector will pick it up |
| `History` paths appear | ✅ Chrome-family detected |
| Browser running as user `agent` | Collector scans `/home/agent` automatically via `/etc/passwd` |
| Firefox under `snap/firefox/common/...` | ✅ Snap Firefox — collector has this path built-in |
| Firefox under `.var/app/org.mozilla.firefox/...` | ✅ Flatpak Firefox — built-in |
| No paths found | Browser never opened — launch it and browse once |

#### Step 4 — Browser Profile Paths Scanned (Linux)

The collector reads `/etc/passwd` and scans every user home for these paths:

| Browser | Standard | Snap | Flatpak |
|---|---|---|---|
| Firefox | `~/.mozilla/firefox/` | `~/snap/firefox/common/.mozilla/firefox/` | `~/.var/app/org.mozilla.firefox/.mozilla/firefox/` |
| Chrome | `~/.config/google-chrome/` | `~/snap/google-chrome/current/.config/google-chrome/` | `~/.var/app/com.google.Chrome/.config/google-chrome/` |
| Chromium | `~/.config/chromium/` | `~/snap/chromium/current/.config/chromium/` | `~/.var/app/org.chromium.Chromium/.config/chromium/` |
| Edge | `~/.config/microsoft-edge/` | `~/snap/microsoft-edge/current/.config/microsoft-edge/` | `~/.var/app/com.microsoft.Edge/.config/microsoft-edge/` |
| Brave | `~/.config/BraveSoftware/Brave-Browser/` | `~/snap/brave/current/.config/BraveSoftware/Brave-Browser/` | `~/.var/app/com.brave.Browser/.config/BraveSoftware/Brave-Browser/` |
| Opera | `~/.config/opera/` | `~/snap/opera/current/.config/opera/` | `~/.var/app/com.opera.Opera/.config/opera/` |
| Vivaldi | `~/.config/vivaldi/` | `~/snap/vivaldi/current/.config/vivaldi/` | `~/.var/app/com.vivaldi.Vivaldi/.config/vivaldi/` |
| Waterfox | `~/.waterfox/` | ❌ | `~/.var/app/net.waterfox.waterfox/.waterfox/` |
| Tor | `~/.tor-browser/.../profile.default/` | ❌ | `~/.var/app/com.github.micahflee.torbrowser-launcher/.../profile.default/` |

#### Step 5 — Expected Log Format

Once a browser is used on the machine, log lines appear like:

```
Apr 13 22:50:01 agent browser-monitor: 2026-04-13 22:50:01 Firefox agent 2h0c42a3.default https://github.com GitHub
Apr 13 22:50:15 agent browser-monitor: 2026-04-13 22:50:15 Chrome agent Default https://google.com Google Search
```

Fields: `timestamp browser username profile url title`

#### Step 6 — Manual ossec.conf Patch (if not auto-applied)

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add before the closing `</ossec_config>` tag:

```xml
<localfile>
  <location>/root/.browser-monitor/browser_history.log</location>
  <log_format>syslog</log_format>
</localfile>
```

Restart agent:
```bash
sudo systemctl restart wazuh-agent
```

#### Step 7 — Service Management

```bash
# Start / Stop / Restart
systemctl start browser-monitor
systemctl stop browser-monitor
systemctl restart browser-monitor

# View last 50 log lines from journald
journalctl -u browser-monitor -n 50 --no-pager

# Update collector to latest version
systemctl stop browser-monitor
curl -sSL https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-history-monitoring/main/collector/browser-history-monitor.py \
  -o /root/.browser-monitor/browser-history-monitor.py
systemctl start browser-monitor
```

#### Uninstall

```bash
systemctl stop browser-monitor
systemctl disable browser-monitor
rm /etc/systemd/system/browser-monitor.service
systemctl daemon-reload
rm -rf /root/.browser-monitor
```

#### Common Issues — Linux

| Symptom | Cause | Fix |
|---|---|---|
| `Failed to connect to bus: No medium found` | `systemctl --user` used instead of SYSTEM | Use `systemctl status browser-monitor` (no `--user`) |
| Log only shows `service_started`, no visits | No browser profiles found | Run the diagnostics in Step 3 above |
| `SyntaxWarning: invalid escape sequence` | Old collector file on disk | Re-download: `curl -sSL .../browser-history-monitor.py -o /root/.browser-monitor/browser-history-monitor.py` |
| `no_browser_profiles_found` in log | Browser never launched or path not covered | Open browser once; run `find / -name 'places.sqlite' 2>/dev/null` |
| Duplicate `<localfile>` in ossec.conf | Installer ran twice | Remove duplicate block with `nano /var/ossec/etc/ossec.conf` |

---

### 🍎 macOS Endpoint

#### Step 1 — Run Installer

```bash
curl -sSL https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-history-monitoring/main/install.sh | bash
```

**The installer automatically:**
- Downloads `browser-history-monitor.py` to `~/.browser-monitor/`
- Creates a **LaunchAgent** plist at `~/Library/LaunchAgents/com.ramkumar.browser-monitor.plist`
- Loads the agent (starts immediately)
- Adds `<localfile>` to `/var/ossec/etc/ossec.conf`
- Restarts the Wazuh agent

#### Step 2 — Grant Full Disk Access (Required on macOS)

macOS TCC protection blocks access to browser databases without this step:

1. Open **System Settings** → **Privacy & Security** → **Full Disk Access**
2. Click **+** and add your Python binary:
   ```bash
   which python3
   # e.g. /opt/homebrew/bin/python3 or /usr/bin/python3
   ```
3. Toggle it **ON**
4. Reload the LaunchAgent:
   ```bash
   launchctl unload ~/Library/LaunchAgents/com.ramkumar.browser-monitor.plist
   launchctl load  ~/Library/LaunchAgents/com.ramkumar.browser-monitor.plist
   ```

#### Step 3 — Verify Installation

```bash
# Check LaunchAgent is loaded
launchctl list | grep browser-monitor

# Watch live log
tail -f ~/.browser-monitor/browser_history.log

# Check Wazuh agent
sudo /Library/Ossec/bin/wazuh-control status
```

#### Step 4 — Verify Browser Profiles are Detected

Run these to confirm the collector can find browser databases on your Mac:

```bash
# Find ALL Firefox places.sqlite files
find / -name "places.sqlite" 2>/dev/null

# Find ALL Firefox profile directories
find / -name "*.default*" -path "*/firefox/*" -type d 2>/dev/null

# Find ALL Chrome/Edge/Brave History SQLite files
find ~/Library/Application\ Support -name "History" -path "*/Default/*" 2>/dev/null
find ~/Library/Application\ Support -name "History" -path "*/Profile*/*" 2>/dev/null

# Find Safari history database
find ~/Library/Safari -name "History.db" 2>/dev/null

# Check which user is running the browser
ps aux | grep -iE 'firefox|chrome|brave|safari|edge|chromium|opera|vivaldi'

# Check current macOS username
whoami
echo $HOME
```

**What to look for:**

| Output | Meaning |
|---|---|
| `places.sqlite` paths appear | ✅ Firefox detected |
| `History` paths appear | ✅ Chrome-family detected |
| `History.db` under `~/Library/Safari` | ✅ Safari detected |
| Nothing found | Browser never opened — launch it and browse once, then re-run |
| `Permission denied` errors | Full Disk Access not yet granted — complete Step 2 |

#### Uninstall

```bash
launchctl unload ~/Library/LaunchAgents/com.ramkumar.browser-monitor.plist
rm ~/Library/LaunchAgents/com.ramkumar.browser-monitor.plist
rm -rf ~/.browser-monitor
```

---

---

## Step 5 — Verify in Dashboard

### 5.1 — Check Archives on Manager

```bash
# All events received
sudo grep 'browser-monitor' /var/ossec/logs/archives/archives.log | tail -10

# Alerts only (rules triggered)
sudo grep 'browser-monitor' /var/ossec/logs/alerts/alerts.log | tail -10
```

### 5.2 — Wazuh Dashboard

1. Open **Wazuh Dashboard** → **Discover**
2. Index: `wazuh-alerts-*`
3. Time range: **Last 24 hours**
4. Filter: `rule.groups: browser_history`
5. Useful columns to add:
   - `agent.name`
   - `data.mon_browser_name`
   - `data.mon_url`
   - `data.mon_browser_profile`
   - `rule.description`
   - `rule.level`

### 5.3 — Test Alert Triggers

Open a browser on a monitored endpoint and visit:

| URL | Expected Rule | Level |
|---|---|---|
| `http://example.com` | 900107 — Insecure HTTP | 3 |
| `https://pastebin.com/test` | 900104 — Data Exfil | 7 |
| `https://mega.nz` | 900104 — Data Exfil | 7 |
| `https://torproject.org` | 900103 — Anonymizer | 8 |
| `https://exploit-db.com` | 900110 — Exploit site | 9 |

### 5.4 — Manual Test via wazuh-logtest (No Browser Needed)

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste:
```
Apr 13 22:41:00 agent browser-monitor: 2026-04-13 22:41:00 Chrome agent Default https://google.com Google Search
```

Expect rule `900100` (level 3 baseline) to fire. For a high-severity test:
```
Apr 13 22:41:00 agent browser-monitor: 2026-04-13 22:41:00 Firefox agent default https://torproject.org Tor Project
```

Expect rule `900103` (level 8 anonymizer) to fire.

---

## Detection Rules Reference

| Rule ID | Level | 🚨 Alert | MITRE |
|---|---|---|---|
| 900100 | 3 | 🟢 Browser visit — baseline visibility (every visit logged) | — |
| 900101 | 10 | 🔴 Dangerous file download (`.exe` `.ps1` `.hta` `.msi` `.iso` `.bat` `.vbs` `.jar` `.dll` `.scr`) | T1204.002 |
| 900102 | 10 | 🔴 Credential / Phishing page (`login` `signin` `verify` `mfa` `otp` `2fa` `reset-password`) | T1566.002 |
| 900103 | 8 | 🟠 Anonymizer / TOR / VPN site (`torproject.org`, `protonvpn`, `nordvpn`, `expressvpn`, `hidemyass`) | T1090 |
| 900104 | 7 | 🟠 Paste / file-sharing site (`pastebin.com`, `mega.nz`, `wetransfer`, `gofile.io`, `privatebin`) | T1567 |
| 900105 | 6 | 🟡 Cloud storage upload (`drive.google.com`, `onedrive`, `dropbox`, `box.com`, `pcloud`) | T1567.002 |
| 900106 | 4 | 🟡 Non-HTTP scheme (`ftp://`, `file://`, `data:`, `blob:`, `javascript:`) | — |
| 900107 | 3 | 🔵 Insecure HTTP visit — excludes LAN/localhost (URL starts `http://`) | — |
| 900108 | 5 | 🟡 Crypto / Trading site (`binance.com`, `coinbase.com`, `metamask.io`, `opensea.io`, `uniswap`) | — |
| 900109 | 3 | 🔵 Social media (`facebook`, `twitter/x.com`, `instagram`, `tiktok`, `discord`, `telegram`) | — |
| 900110 | 9 | 🔴 Exploit / Hacking tool site (`exploit-db.com`, `shodan.io`, `censys.io`, `nulled.to`, `crackstation`) | T1588.005 |
| 900111 | 9 | 🔴 Dark web / `.onion` proxy access (`.onion`, `onion.to`, `onion.ws`, `darkweb`) | T1090.003 |
| 900112 | 8 | 🟠 Malware keyword in URL (`malware`, `ransomware`, `trojan`, `keylogger`, `botnet`, `dropper`) | T1566 |
| 900113 | 3 | ⚪ Service lifecycle event — collector startup / shutdown on agent | — |
| 900114 | 3 | 🔵 Background / Redirect — No Title entries suppressed from dashboard | — |
| 900115 | 3 | 🔵 Gaming site (`steam`, `epicgames`, `xbox`, `roblox`, `twitch`, `minecraft`, `battle.net`) | — |
| 900116 | 3 | 🔵 Streaming / Entertainment (`youtube`, `netflix`, `spotify`, `hotstar`, `disney+`, `primevideo`) | — |
| 900117 | 3 | 🔵 AI / GenAI platform (`chatgpt`, `claude.ai`, `gemini`, `copilot`, `perplexity.ai`, `huggingface`) | — |
| 900118 | 3 | 🔵 Shopping / E-commerce (`amazon`, `flipkart`, `ebay`, `aliexpress`, `myntra`, `shopify`) | — |
| 900119 | 3 | 🔵 News / Media site (`bbc`, `cnn`, `ndtv`, `thehindu`, `techcrunch`, `thehackernews`) | — |
| 900120 | 3 | 🔵 Developer / DevOps tools (`github`, `gitlab`, `stackoverflow`, `docker`, `pypi`, `elastic`) | — |
| 900121 | 10 | 🔴 Adult / Inappropriate content detected | — |
| 900122 | 3 | 🟢 Catch-all — Any URL not matched above (100% visit visibility) | — |

---

## 📊 Rules Summary

| Rule ID | Level | Category | Example Match |
|---|---|---|---|
| 900100 | 3 | Baseline visibility | Any browser visit |
| 900101 | 10 | Dangerous download | `.exe` `.ps1` `.hta` `.msi` `.iso` `.bat` `.vbs` `.dll` in URL |
| 900102 | 10 | Phishing / Credential | `login` `mfa` `verify` `otp` `2fa` `password-reset` in URL |
| 900103 | 8 | Anonymizer / TOR | `torproject.org`, `protonvpn`, `nordvpn`, `expressvpn` |
| 900104 | 7 | Data exfiltration | `pastebin.com`, `mega.nz`, `wetransfer`, `gofile.io` |
| 900105 | 6 | Cloud storage upload | `drive.google.com`, `onedrive`, `dropbox`, `pcloud` |
| 900106 | 4 | Non-HTTP scheme | `ftp://`, `file://`, `data:`, `blob:`, `javascript:` |
| 900107 | 3 | Insecure HTTP | URL starts `http://` (not https, excludes LAN) |
| 900108 | 5 | Crypto / Trading | `binance.com`, `coinbase.com`, `metamask.io`, `opensea.io` |
| 900109 | 3 | Social Media | `facebook`, `x.com`, `instagram`, `tiktok`, `discord` |
| 900110 | 9 | Exploit / Hacking tool | `exploit-db.com`, `shodan.io`, `censys.io`, `nulled.to` |
| 900111 | 9 | Dark web / .onion proxy | `.onion`, `dark.fail`, `ahmia.fi`, `onion.to` |
| 900112 | 8 | Malware keyword in URL | `malware`, `ransomware`, `botnet`, `trojan`, `dropper` |
| 900113 | 3 | Service lifecycle | Collector startup / shutdown message |
| 900114 | 3 | Background / Redirect | No Title entries — background requests suppressed |
| 900115 | 3 | Gaming sites | `steam`, `epicgames`, `xbox`, `roblox`, `twitch` |
| 900116 | 3 | Streaming / Entertainment | `youtube`, `netflix`, `spotify`, `hotstar`, `disneyplus` |
| 900117 | 3 | AI / GenAI platforms | `chatgpt`, `claude.ai`, `gemini`, `perplexity.ai` |
| 900118 | 3 | Shopping / E-commerce | `amazon`, `flipkart`, `ebay`, `aliexpress`, `myntra` |
| 900119 | 3 | News / Media | `bbc`, `cnn`, `ndtv`, `thehindu`, `thehackernews` |
| 900120 | 3 | Developer / DevOps tools | `github`, `gitlab`, `stackoverflow`, `docker`, `pypi` |
| 900121 | 10 | Adult / Inappropriate content | Explicit site domains |
| 900122 | 3 | Catch-all general visit | Any `https://` URL not matched by rules above |

---

## 🎯 Quick Detection Summary

### By Severity

| Severity | Level Range | Rules | Count |
|---|---|---|---|
| 🔴 Critical | 9 – 10 | 900101, 900102, 900110, 900111, 900121 | 5 |
| 🟠 High | 7 – 8 | 900103, 900104, 900112 | 3 |
| 🟡 Medium | 4 – 6 | 900105, 900106, 900108 | 3 |
| 🔵 Low | 1 – 3 | 900100, 900107, 900109, 900113, 900114, 900115, 900116, 900117, 900118, 900119, 900120, 900122 | 12 |

### By Detection Category

| 🗂️ Category | Rules |
|---|---|
| 🦠 Malware & Exploit Activity | 900101, 900110, 900112 |
| 🎣 Phishing & Credential Theft | 900102 |
| 🕵️ Anonymization & Evasion | 900103, 900111 |
| 📤 Data Exfiltration | 900104, 900105, 900106 |
| 📡 Risky Browsing Behavior | 900107, 900108, 900109, 900121 |
| 🎮 Productivity Monitoring | 900115, 900116, 900117, 900118, 900119, 900120 |
| ✅ Baseline & Audit | 900100, 900113, 900114, 900122 |

### 🗺️ MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Rule |
|---|---|---|---|
| T1204.002 | User Execution: Malicious File | Execution | 900101 |
| T1566.002 | Phishing: Spearphishing Link | Initial Access | 900102 |
| T1566 | Phishing (generic) | Initial Access | 900112 |
| T1090 | Proxy / Anonymizer | C2 | 900103 |
| T1090.003 | Multi-hop Proxy / Dark Web | C2 | 900111 |
| T1567 | Exfiltration Over Web Service | Exfiltration | 900104 |
| T1567.002 | Exfiltration to Cloud Storage | Exfiltration | 900105 |
| T1588.005 | Obtain Capabilities: Exploits | Resource Dev | 900110 |

> ✅ **23 Rules | IDs 900100–900122 | 8 MITRE Techniques | Version 2.8**  
> **Tactics Covered: Initial Access · Execution · Exfiltration · C2 · Resource Development**

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `Failed to connect to bus` on `--user` (Linux) | Use `systemctl status browser-monitor` (SYSTEM service — no `--user` flag) |
| Log only has `service_started`, no visits | Run browser profile diagnostics (Phase 2 Step 3 for your OS) |
| `SyntaxWarning: invalid escape sequence` | Old collector file — re-download and restart service |
| `no_browser_profiles_found` in log | Browser not installed or never launched — open browser once to create profile |
| Duplicate `<localfile>` in ossec.conf | Installer ran twice — remove duplicate block manually |
| No alerts in Dashboard | Run `wazuh-logtest` with a test line — check Phase 3 output for rule match |
| macOS: permission denied on browser DB | Grant Full Disk Access to python3 in System Settings → Privacy & Security |
| Windows: log file empty | Run `Start-ScheduledTask -TaskName 'BrowserHistoryMonitor'` |
| Windows: Python not found | Reinstall Python — check "Install for All Users" + "Add to PATH" |
| Agent not forwarding to manager | Confirm `<localfile>` block is in `ossec.conf` pointing to correct log path |
| analysisd validation error | `sudo /var/ossec/bin/wazuh-analysisd -t` — look for ERROR lines in decoder/rule XML |
| Rule ID conflict | Remove any old 110100–110114 blocks from `local_rules.xml` |

---

## Repo Structure

```
wazuh-browser-history-monitoring/
├── README.md                                    ← This guide
├── LICENSE                                      ← MIT
├── install.ps1                                  ← Windows one-liner bootstrap
├── install.sh                                   ← Linux/macOS one-liner bootstrap
├── collector/
│   └── browser-history-monitor.py              ← Python collector v2.3 (Win/Linux/macOS)
├── installers/
│   ├── windows-installer.ps1                   ← Windows full installer (VT-clean)
│   ├── linux-installer.sh                      ← Linux installer (systemd SYSTEM service)
│   └── macos-installer.sh                      ← macOS installer (LaunchAgent)
└── wazuh/
    ├── decoders/
    │   └── 0310-browser_history_decoder.xml    ← Wazuh decoder
    └── rules/
        └── 0310-browser_history_rules.xml      ← 23 detection rules (MITRE mapped, IDs 900100–900122)
```

---

> **IT Fortress SOC** | Built by [Ram Kumar G](https://github.com/Ramkumar2545) | Wazuh v4.x | April 2026  
> VirusTotal-clean · No EXE downloads · No third-party URLs · MIT License
