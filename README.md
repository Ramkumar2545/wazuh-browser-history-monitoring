# 🌐 Wazuh Browser History Monitoring

> **Real-time browser history monitoring** integrated with **Wazuh SIEM** — monitor Chrome, Edge, Brave, Firefox, Opera, and Safari across **Windows, Linux, and macOS** endpoints with security alerts on the Wazuh Dashboard.

[![Wazuh](https://img.shields.io/badge/Wazuh-4.x-blue?style=flat-square)](https://wazuh.com)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)](#)
[![Python](https://img.shields.io/badge/Python-3.8%2B-green?style=flat-square)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

---

## 📋 Table of Contents

1. [Architecture](#architecture)
2. [Supported Browsers](#supported-browsers)
3. [Prerequisites](#prerequisites)
4. [Step 1 — Wazuh Manager Setup](#step-1--wazuh-manager-setup)
5. [Step 2 — Windows Endpoint](#step-2--windows-endpoint)
6. [Step 3 — Linux Endpoint](#step-3--linux-endpoint)
7. [Step 4 — macOS Endpoint](#step-4--macos-endpoint)
8. [Step 5 — Verify in Dashboard](#step-5--verify-in-dashboard)
9. [Detection Rules](#detection-rules)
10. [Troubleshooting](#troubleshooting)
11. [Repo Structure](#repo-structure)

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  WAZUH MANAGER                      │
│  ┌─────────────────┐   ┌────────────────────────┐   │
│  │ Decoder          │──▶│ Rules (110100–110114)  │   │
│  │ browser_history  │   │ Alerts → Dashboard     │   │
│  └─────────────────┘   └────────────────────────┘   │
└──────────────────────────────┬──────────────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                    ▼
   Wazuh Agent           Wazuh Agent          Wazuh Agent
   (Windows)              (Linux)              (macOS)
          │                    │                    │
  browser-history-monitor.py (Python) or .ps1 (PowerShell)
  reads SQLite DBs every 60s → writes browser_history.log
```

**How it works:**
1. Collector script reads browser SQLite databases every 60 seconds
2. Writes new visit entries as syslog+JSON lines to a log file
3. Wazuh agent monitors the log file and ships events to manager
4. Custom decoder parses the log fields
5. Custom rules fire alerts based on URL patterns
6. Alerts appear in Wazuh Dashboard with MITRE ATT&CK mapping

---

## Supported Browsers

| Browser | Windows | Linux | macOS |
|---|---|---|---|
| Google Chrome | ✅ | ✅ | ✅ |
| Microsoft Edge | ✅ | ✅ | ✅ |
| Brave | ✅ | ✅ | ✅ |
| Firefox | ✅ | ✅ | ✅ |
| Opera / Opera GX | ✅ | ✅ | ✅ |
| Safari | ❌ | ❌ | ✅ |
| Chromium | ❌ | ✅ | ❌ |

---

## Prerequisites

| Component | Requirement |
|---|---|
| Wazuh Manager | v4.x |
| Wazuh Agent | Installed and enrolled on each endpoint |
| Windows | Windows 10/11, Server 2016+, Python 3.8+ (system-wide) |
| Linux | Ubuntu 20.04+, Debian 11+, AlmaLinux 8+, RHEL 8+, Python 3.8+ |
| macOS | macOS 12+ (Monterey+), Python 3.8+ |

> ⚠️ **Python must be installed system-wide on Windows** (check "Install for All Users" during setup) so the scheduled task running under `BUILTIN\Users` can access it.

---

## Step 1 — Wazuh Manager Setup

> 🖥️ **Run once on your Wazuh Manager server. This applies to ALL endpoints.**

### 1.1 — Clone the Repository

```bash
cd /tmp
git clone https://github.com/Ramkumar2545/wazuh-browser-history-monitoring.git
cd wazuh-browser-history-monitoring
```

### 1.2 — Deploy the Decoder

```bash
sudo cp wazuh/decoders/0310-browser_history_decoder.xml /var/ossec/etc/decoders/
sudo chown wazuh:wazuh /var/ossec/etc/decoders/0310-browser_history_decoder.xml
sudo chmod 660 /var/ossec/etc/decoders/0310-browser_history_decoder.xml
```

### 1.3 — Deploy the Rules

```bash
sudo cp wazuh/rules/0310-browser_history_rules.xml /var/ossec/etc/rules/
sudo chown wazuh:wazuh /var/ossec/etc/rules/0310-browser_history_rules.xml
sudo chmod 660 /var/ossec/etc/rules/0310-browser_history_rules.xml
```

### 1.4 — Validate

```bash
# Must show no ERROR or CRITICAL lines
sudo /var/ossec/bin/wazuh-analysisd -t
```

### 1.5 — Restart Manager

```bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
```

### 1.6 — Test with wazuh-logtest

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste this test log line:
```
Apr 13 06:27:55 WIN-ENDPOINT browser-monitor: 2026-04-13 06:27:55 Chrome Default https://pastebin.com/xyz No Title
```

Expected output — Phase 3:
```
** Alert to be generated.
Rule id: '110104'
Level: '7'
Description: 'Browser: Data-Sharing/Paste Site Visit'
```

✅ **Manager is ready. Now set up each endpoint.**

---

## Step 2 — Windows Endpoint

> 🪟 Run on each Windows machine. **Open PowerShell as Administrator.**

### 2.1 — Check Prerequisites

```powershell
# Wazuh agent must be running
Get-Service WazuhSvc

# Python must be installed system-wide
# If NOT installed: download from https://python.org
# During install: check "Add to PATH" AND "Install for All Users"
python --version
```

### 2.2 — Clone the Repo

```powershell
cd C:\
git clone https://github.com/Ramkumar2545/wazuh-browser-history-monitoring.git
cd C:\wazuh-browser-history-monitoring\installers
```

### 2.3 — Run the Installer

```powershell
# Run as Administrator — no internet downloads
powershell.exe -ExecutionPolicy Bypass -File windows-installer.ps1
```

Expected output:
```
[*] Wazuh Browser Monitor - Windows Installer
[+] Found System Python: C:\Program Files\Python312\python.exe
[+] Found Windowless Python: C:\Program Files\Python312\pythonw.exe
[+] Created C:\BrowserMonitor
[+] Granted Modify permissions to Users
[+] Copied collector to C:\BrowserMonitor\browser-history-monitor.py
[+] Scheduled Task created: BrowserHistoryMonitor
[+] Startup shortcut created
[+] ossec.conf updated
[+] Wazuh agent restarted
[SUCCESS] Installation complete!
```

### 2.4 — Start Monitoring Immediately

```powershell
# Trigger task now (normally runs at logon)
Start-ScheduledTask -TaskName 'BrowserHistoryMonitor'

# Wait 30 seconds, then check
Start-Sleep 30
Get-Content 'C:\BrowserMonitor\browser_history.log' -Tail 10
```

Expected log format:
```
Apr 13 11:00:01 WIN-ENDPOINT browser-monitor: 2026-04-13 11:00:01 Chrome Default https://google.com Google
```

### 2.5 — Verify Agent is Forwarding

```powershell
Get-Content 'C:\Program Files (x86)\ossec-agent\ossec.log' -Tail 20 | Select-String 'browser_history'
```

### 2.6 — Uninstall

```powershell
Unregister-ScheduledTask -TaskName 'BrowserHistoryMonitor' -Confirm:$false
Remove-Item 'C:\BrowserMonitor' -Recurse -Force
```

---

## Step 3 — Linux Endpoint

> 🐧 Run on each Linux machine (Ubuntu, Debian, AlmaLinux, RHEL, CentOS).

### 3.1 — Check Prerequisites

```bash
# Wazuh agent must be running
systemctl status wazuh-agent

# Python3 must be installed
python3 --version

# Install if missing:
# Ubuntu/Debian:    sudo apt install -y python3
# AlmaLinux/RHEL:   sudo dnf install -y python3
```

### 3.2 — Clone the Repo

```bash
cd /tmp
git clone https://github.com/Ramkumar2545/wazuh-browser-history-monitoring.git
cd wazuh-browser-history-monitoring/installers
```

### 3.3 — Run the Installer

```bash
# No root required — installs to user's home
bash linux-installer.sh
```

### 3.4 — Verify

```bash
# Check systemd user service
systemctl --user status browser-monitor

# Watch log output
tail -f ~/.browser-monitor/browser_history.log
```

### 3.5 — Add Log to Wazuh Agent (Manual if not auto-added)

Edit `/var/ossec/etc/ossec.conf` and add inside `<ossec_config>`:

```xml
<localfile>
  <location>/home/YOUR_USERNAME/.browser-monitor/browser_history.log</location>
  <log_format>syslog</log_format>
</localfile>
```

Then restart agent:
```bash
sudo systemctl restart wazuh-agent
```

### 3.6 — Uninstall

```bash
systemctl --user stop browser-monitor
systemctl --user disable browser-monitor
rm ~/.config/systemd/user/browser-monitor.service
rm -rf ~/.browser-monitor
```

---

## Step 4 — macOS Endpoint

> 🍎 Run on each macOS machine (Monterey 12+, Ventura 13+, Sonoma 14+).

### 4.1 — Check Prerequisites

```bash
# Wazuh agent
/Library/Ossec/bin/wazuh-control status

# Python3
python3 --version
# Install if missing: brew install python3
```

### 4.2 — Clone the Repo

```bash
cd /tmp
git clone https://github.com/Ramkumar2545/wazuh-browser-history-monitoring.git
cd wazuh-browser-history-monitoring/installers
```

### 4.3 — Run the Installer

```bash
# No sudo needed — installs as current user
bash macos-installer.sh
```

### 4.4 — ⚠️ Grant Full Disk Access (Required for Safari + all browsers)

macOS TCC protection blocks access to browser databases:

1. Open **System Settings** → **Privacy & Security** → **Full Disk Access**
2. Click **+** and add the Python binary:
   ```bash
   which python3
   # e.g. /usr/bin/python3 or /opt/homebrew/bin/python3
   ```
3. Toggle it **ON**
4. Reload the service:
   ```bash
   launchctl unload ~/Library/LaunchAgents/com.ramkumar.browser-monitor.plist
   launchctl load ~/Library/LaunchAgents/com.ramkumar.browser-monitor.plist
   ```

### 4.5 — Verify

```bash
# Check LaunchAgent
launchctl list | grep browser-monitor

# Watch log
tail -f ~/.browser-monitor/browser_history.log
```

### 4.6 — Uninstall

```bash
launchctl unload ~/Library/LaunchAgents/com.ramkumar.browser-monitor.plist
rm ~/Library/LaunchAgents/com.ramkumar.browser-monitor.plist
rm -rf ~/.browser-monitor
```

---

## Step 5 — Verify in Dashboard

### 5.1 — Check Archives on Manager

```bash
sudo grep 'browser-monitor' /var/ossec/logs/archives/archives.log | tail -10
```

### 5.2 — Check Alerts

```bash
sudo grep 'browser-monitor' /var/ossec/logs/alerts/alerts.log | tail -10
```

### 5.3 — Wazuh Dashboard

1. Open Wazuh Dashboard → **Discover**
2. Index pattern: `wazuh-alerts-*`
3. Time: **Last 24 hours**
4. Search: `rule.groups: "browser_history"`
5. Add columns: `agent.name`, `data.browser`, `data.url`, `data.profile`, `rule.description`

### 5.4 — Test Rule Triggers

On a monitored endpoint, open a browser and visit:
- `http://example.com` → Rule **110107** (Insecure HTTP)
- `https://pastebin.com` → Rule **110104** (Data Exfil)
- `https://mega.nz` → Rule **110104** (Data Exfil)
- `https://torproject.org` → Rule **110103** (Anonymizer)

---

## Detection Rules

| Rule ID | Level | Alert | MITRE |
|---|---|---|---|
| 110100 | 2 | Browser visit (baseline visibility) | — |
| 110101 | 10 | Dangerous file download (.exe .ps1 .hta .msi .iso) | T1204.002 |
| 110102 | 10 | Credential/phishing page (login, mfa, verify, otp) | T1566.002 |
| 110103 | 8 | Anonymizer / TOR access | T1090 |
| 110104 | 7 | Paste/file-sharing site (Pastebin, Mega, WeTransfer) | T1567 |
| 110105 | 6 | Cloud storage (Drive, OneDrive, Dropbox, Box) | T1567.002 |
| 110106 | 4 | Non-HTTP scheme (ftp, file, data, blob) | — |
| 110107 | 3 | Insecure HTTP visit | — |
| 110108 | 5 | Crypto/trading site (Binance, Coinbase, Kraken) | — |
| 110109 | 3 | Social media (Facebook, Twitter, TikTok, Instagram) | — |
| 110110 | 9 | Exploit/hacking tool site (exploit-db, Shodan) | T1588.005 |
| 110111 | 9 | Dark web / .onion proxy access | T1090.003 |
| 110112 | 8 | Malware keyword in domain | T1566 |
| 110113 | 3 | Browser extension installed/updated | — |
| 110114 | 1 | Monitor service started | — |

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Log file empty (Windows) | `Start-ScheduledTask -TaskName 'BrowserHistoryMonitor'` |
| Scheduled task not running | Check `Get-ScheduledTask -TaskName 'BrowserHistoryMonitor'` |
| Linux service fails | `systemctl --user status browser-monitor` and `journalctl --user -u browser-monitor -n 50` |
| macOS permission denied | Grant Full Disk Access to python3 — see Step 4.4 |
| No alerts in dashboard | Run `wazuh-logtest` on manager, paste a log line, check Phase 3 |
| analysisd test error | `sudo /var/ossec/bin/wazuh-analysisd -t` — look for ERROR lines |
| Agent not forwarding | Check `ossec.conf` has the `<localfile>` block with correct log path |

---

## Repo Structure

```
wazuh-browser-history-monitoring/
├── README.md
├── collector/
│   └── browser-history-monitor.py     ← Main Python collector (Win/Linux/macOS)
├── installers/
│   ├── windows-installer.ps1          ← Windows setup (VT-clean, no downloads)
│   ├── linux-installer.sh             ← Linux setup (Ubuntu/Debian/AlmaLinux/RHEL)
│   └── macos-installer.sh             ← macOS setup (Monterey/Ventura/Sonoma)
└── wazuh/
    ├── decoders/
    │   └── 0310-browser_history_decoder.xml
    └── rules/
        └── 0310-browser_history_rules.xml
```

---

## Credits

Inspired by [bayusky/wazuh-custom-rules-and-decoders](https://github.com/bayusky/wazuh-custom-rules-and-decoders/tree/main/browser-monitoring) and the [Medium article](https://medium.com/@bayusangkaya/unlocking-endpoint-visibility-real-time-browser-history-monitoring-with-wazuh-8459b86d3e14) by Bayu Sangkaya.

Rebuilt by **Ram Kumar G (IT Fortress)** — rewritten to be VT-clean (no `Invoke-WebRequest`, no exe downloads, no remote script fetching) and extended with macOS support, MITRE mapping, and full multi-profile detection.

---

**IT Fortress SOC | Wazuh v4.14.x | April 2026**
