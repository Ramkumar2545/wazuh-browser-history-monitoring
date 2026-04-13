# 🌐 Wazuh Browser History Monitoring

> **Real-time browser history monitoring** integrated with **Wazuh SIEM** — monitor Chrome, Edge, Brave, Firefox, Opera, and Safari across **Windows, Linux, and macOS** endpoints with security alerts on the Wazuh Dashboard.

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
- [🚀 PHASE 2 — Endpoint One-Liner Deploy](#-phase-2--endpoint-one-liner-deploy)
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
│  │ Decoder               │─▶│ Rules (110100–110114)  ││
│  │ 0310-browser_history  │  │ Alerts → Dashboard     ││
│  └──────────────────────┘  └────────────────────────┘│
└───────────────────────────────┬──────────────────────┘
                                │  Wazuh Agent (enrolled)
          ┌─────────────────────┼─────────────────────┐
          ▼                     ▼                     ▼
   Windows Endpoint       Linux Endpoint       macOS Endpoint
  (Scheduled Task)      (systemd user svc)  (LaunchAgent)
          │                     │                     │
   browser-history-monitor.py  ←  reads SQLite DBs every 60s
          │
   writes → browser_history.log
          │
   <localfile> in ossec.conf  →  Wazuh Agent  →  Manager
```

**Flow:**
1. Collector reads browser SQLite DBs every 60 seconds
2. Writes new visits as `syslog+JSON` lines to a log file
3. Wazuh agent ships the log file to the manager
4. Decoder parses fields (browser, URL, profile, user, host)
5. Rules fire alerts based on URL patterns & risk categories
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
| Wazuh Agent | Installed & enrolled on each endpoint |
| Windows | Windows 10/11 / Server 2016+, Python 3.8+ (system-wide) |
| Linux | Ubuntu 20.04+, Debian 11+, AlmaLinux 8+, RHEL 8+, Python 3.8+ |
| macOS | macOS 12+ (Monterey+), Python 3.8+ |

> ⚠️ **Python must be installed system-wide on Windows** — check "Install for All Users" and "Add to PATH" during setup.

---

---

## ⚙️ PHASE 1 — Wazuh Manager Setup *(Do this ONCE on the Manager)*

> 🖥️ These steps run **only on your Wazuh Manager server** and enable detection for ALL enrolled endpoints automatically. No per-endpoint changes needed on the manager side.

### 1.1 — Deploy the Decoder

The decoder teaches Wazuh how to parse the browser history log lines into structured fields (`browser`, `url`, `profile`, `user`, `hostname`).

```bash
# Clone the repo
cd /tmp
git clone https://github.com/Ramkumar2545/wazuh-browser-history-monitoring.git
cd wazuh-browser-history-monitoring

# Copy decoder
sudo cp wazuh/decoders/0310-browser_history_decoder.xml /var/ossec/etc/decoders/
sudo chown wazuh:wazuh /var/ossec/etc/decoders/0310-browser_history_decoder.xml
sudo chmod 660 /var/ossec/etc/decoders/0310-browser_history_decoder.xml

# Verify it was copied
ls -lah /var/ossec/etc/decoders/0310-browser_history_decoder.xml
```

**What's inside the decoder:**
```xml
<!-- /var/ossec/etc/decoders/0310-browser_history_decoder.xml -->
<decoder name="browser-history">
  <prematch>browser-monitor:</prematch>
  <regex>(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\w+) (\S+) (https?://\S+) (.*)</regex>
  <order>visit_time, browser, profile, url, title</order>
</decoder>
```

---

### 1.2 — Deploy the Rules

The rules define what gets alerted — 14 rules covering dangerous downloads, phishing pages, anonymizer tools, data exfiltration sites, dark web proxies, and more.

```bash
# Copy rules
sudo cp wazuh/rules/0310-browser_history_rules.xml /var/ossec/etc/rules/
sudo chown wazuh:wazuh /var/ossec/etc/rules/0310-browser_history_rules.xml
sudo chmod 660 /var/ossec/etc/rules/0310-browser_history_rules.xml

# Verify
ls -lah /var/ossec/etc/rules/0310-browser_history_rules.xml
```

**Rules summary — what fires an alert:**

| Rule ID | Level | Category | Example Match |
|---|---|---|---|
| 110100 | 2 | Baseline visibility | Any browser visit |
| 110101 | 10 | Dangerous download | `.exe` `.ps1` `.hta` `.msi` `.iso` in URL |
| 110102 | 10 | Phishing / Credential | `login` `mfa` `verify` `otp` `password-reset` in URL |
| 110103 | 8 | Anonymizer / TOR | `torproject.org`, `protonvpn`, `nordvpn` |
| 110104 | 7 | Data exfiltration | `pastebin.com`, `mega.nz`, `wetransfer` |
| 110105 | 6 | Cloud storage upload | `drive.google.com`, `onedrive`, `dropbox` |
| 110106 | 4 | Non-HTTP scheme | `ftp://`, `file://`, `data:`, `blob:` |
| 110107 | 3 | Insecure HTTP | URL starts with `http://` (not https) |
| 110108 | 5 | Crypto / Trading | `binance.com`, `coinbase.com`, `kraken.com` |
| 110109 | 3 | Social Media | `facebook`, `twitter`, `tiktok`, `instagram` |
| 110110 | 9 | Exploit / Hacking tool | `exploit-db.com`, `shodan.io`, `hackforums` |
| 110111 | 9 | Dark web / .onion proxy | `.onion`, `dark.fail`, `ahmia.fi` |
| 110112 | 8 | Malware keyword in domain | `malware`, `ransomware`, `botnet` in domain |
| 110113 | 3 | Extension install/update | `chrome.google.com/webstore`, `addons.mozilla` |
| 110114 | 1 | Monitor service started | Collector startup message |

---

### 1.3 — Update `ossec.conf` on Manager *(Optional — Centralised Log Pull)*

> This step is only needed if you want the **manager** to directly pull log files from agents using agent-less or shared config. In most deployments, the **agent's** `ossec.conf` handles the `<localfile>` (done automatically in Phase 2). Skip this step unless you use centralised config.

If you use **centralised configuration** (agent groups), add to the agent group's shared `agent.conf`:

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
    <location>/home/*/.browser-monitor/browser_history.log</location>
    <log_format>syslog</log_format>
  </localfile>
</agent_config>

<!-- Browser Monitor: macOS -->
<agent_config os="Darwin">
  <localfile>
    <location>/Users/*/.browser-monitor/browser_history.log</location>
    <log_format>syslog</log_format>
  </localfile>
</agent_config>
```

Save and reload:
```bash
sudo systemctl restart wazuh-manager
```

---

### 1.4 — Validate & Restart Manager

```bash
# Check for ERROR or CRITICAL — should show no issues
sudo /var/ossec/bin/wazuh-analysisd -t

# Restart manager
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
```

Expected output:
```
● wazuh-manager.service - Wazuh manager
   Active: active (running)
```

---

### 1.5 — Test with `wazuh-logtest`

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste this test line when prompted:
```
Apr 13 06:27:55 WIN-ENDPOINT browser-monitor: 2026-04-13 06:27:55 Chrome Default https://pastebin.com/xyz No Title
```

**Expected Phase 3 result:**
```
** Alert to be generated.
Rule id: '110104'
Level: '7'
Description: 'Browser: Data-Sharing/Paste Site Visit'
```

✅ **Phase 1 complete — Manager is ready. All enrolled agents will now have active detection.**

---

---

## 🚀 PHASE 2 — Endpoint One-Liner Deploy

> These commands run **on each endpoint** (Windows, Linux, or macOS).  
> No manual file copying. The one-liner downloads only the Python collector from your own public repo — no EXE downloads, no third-party URLs.

### ✅ What the One-Liner Does Automatically

| Step | Action |
|---|---|
| ① | Checks for **Administrator/root** privileges |
| ② | Detects **System-Wide Python 3** (fails cleanly if missing with install instructions) |
| ③ | Creates install directory with correct ACL permissions |
| ④ | Downloads **only** `browser-history-monitor.py` from `github.com/Ramkumar2545` |
| ⑤ | Creates **Scheduled Task / systemd service / LaunchAgent** (runs hidden at every logon) |
| ⑥ | Creates **All-Users Startup shortcut** (Windows failsafe) |
| ⑦ | Auto-patches `ossec.conf` with the correct `<localfile>` block |
| ⑧ | Restarts **Wazuh agent** |
| ⑨ | Starts monitoring **immediately** |

---

### 🪟 Windows Endpoint

> Open **PowerShell as Administrator** and run:

```powershell
powershell -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; iwr -UseBasicParsing 'https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-history-monitoring/main/install.ps1' | iex"
```

**Pre-requirement — Python must be installed first:**
```
If Python is missing, the script stops and shows:

  ACTION REQUIRED:
  1. Download from: https://python.org/downloads
  2. During install, CHECK:
       [x] Install for All Users
       [x] Add Python to PATH
  3. Re-run the one-liner.
```

**Verify after install:**
```powershell
# Watch live browser history log
Get-Content 'C:\BrowserMonitor\browser_history.log' -Tail 20 -Wait

# Check scheduled task
Get-ScheduledTask -TaskName 'BrowserHistoryMonitor'

# Check Wazuh agent is running
Get-Service WazuhSvc
```

**Expected log format:**
```
Apr 13 11:00:01 WIN-PC browser-monitor: 2026-04-13 11:00:01 Chrome Default https://google.com Google
```

**Uninstall:**
```powershell
Unregister-ScheduledTask -TaskName 'BrowserHistoryMonitor' -Confirm:$false
Remove-Item 'C:\BrowserMonitor' -Recurse -Force
```

---

### 🐧 Linux Endpoint

> Run in terminal:

```bash
curl -sSL https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-history-monitoring/main/install.sh | bash
```

Or with wget:
```bash
wget -qO- https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-history-monitoring/main/install.sh | bash
```

**Verify after install:**
```bash
# Check systemd user service
systemctl --user status browser-monitor

# Watch live logs
tail -f ~/.browser-monitor/browser_history.log

# Check Wazuh agent
sudo systemctl status wazuh-agent
```

**Manual ossec.conf patch (if not auto-applied):**
```bash
sudo nano /var/ossec/etc/ossec.conf
```
Add inside `<ossec_config>`:
```xml
<localfile>
  <location>/home/YOUR_USERNAME/.browser-monitor/browser_history.log</location>
  <log_format>syslog</log_format>
</localfile>
```
```bash
sudo systemctl restart wazuh-agent
```

**Uninstall:**
```bash
systemctl --user stop browser-monitor && systemctl --user disable browser-monitor
rm ~/.config/systemd/user/browser-monitor.service
rm -rf ~/.browser-monitor
```

---

### 🍎 macOS Endpoint

> Run in terminal:

```bash
curl -sSL https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-history-monitoring/main/install.sh | bash
```

**⚠️ Required after install — Grant Full Disk Access:**

macOS TCC protection blocks access to browser databases without this:

1. Open **System Settings** → **Privacy & Security** → **Full Disk Access**
2. Click **+** → add your Python binary:
   ```bash
   which python3
   # e.g. /opt/homebrew/bin/python3
   ```
3. Toggle it **ON**
4. Reload the agent:
   ```bash
   launchctl unload ~/Library/LaunchAgents/com.ramkumar.browser-monitor.plist
   launchctl load ~/Library/LaunchAgents/com.ramkumar.browser-monitor.plist
   ```

**Verify:**
```bash
launchctl list | grep browser-monitor
tail -f ~/.browser-monitor/browser_history.log
```

**Uninstall:**
```bash
launchctl unload ~/Library/LaunchAgents/com.ramkumar.browser-monitor.plist
rm ~/Library/LaunchAgents/com.ramkumar.browser-monitor.plist
rm -rf ~/.browser-monitor
```

---

---

## Step 5 — Verify in Dashboard

### 5.1 — Check Logs on Manager

```bash
# Archives (all events)
sudo grep 'browser-monitor' /var/ossec/logs/archives/archives.log | tail -10

# Alerts only (rules triggered)
sudo grep 'browser-monitor' /var/ossec/logs/alerts/alerts.log | tail -10
```

### 5.2 — Wazuh Dashboard

1. Open **Wazuh Dashboard** → **Discover**
2. Index: `wazuh-alerts-*`
3. Time range: **Last 24 hours**
4. Search: `rule.groups: "browser_history"`
5. Add columns:
   - `agent.name`
   - `data.browser`
   - `data.url`
   - `data.profile`
   - `rule.description`
   - `rule.level`

### 5.3 — Test Alert Triggers

Open a browser on a monitored endpoint and visit:

| URL | Expected Rule | Level |
|---|---|---|
| `http://example.com` | 110107 — Insecure HTTP | 3 |
| `https://pastebin.com/test` | 110104 — Data Exfil | 7 |
| `https://mega.nz` | 110104 — Data Exfil | 7 |
| `https://torproject.org` | 110103 — Anonymizer | 8 |
| `https://exploit-db.com` | 110110 — Exploit site | 9 |

---

## Detection Rules Reference

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
| Scheduled task not running | `Get-ScheduledTask -TaskName 'BrowserHistoryMonitor' \| Select-Object State` |
| Linux service fails | `systemctl --user status browser-monitor` + `journalctl --user -u browser-monitor -n 50` |
| macOS permission denied | Grant Full Disk Access to python3 — see Phase 2 macOS section |
| No alerts in dashboard | Run `sudo /var/ossec/bin/wazuh-logtest` → paste a test log line → check Phase 3 output |
| analysisd test error | `sudo /var/ossec/bin/wazuh-analysisd -t` — look for ERROR lines |
| Agent not forwarding | Check `ossec.conf` has the correct `<localfile>` block pointing to the log file |
| Python not found (Windows) | Reinstall Python: check "Install for All Users" + "Add to PATH" |
| ossec.conf not updated | Add `<localfile>` block manually — see Phase 2 manual patch section |

---

## Repo Structure

```
wazuh-browser-history-monitoring/
├── README.md                                    ← This guide
├── LICENSE                                      ← MIT
├── install.ps1                                  ← Windows one-liner bootstrap
├── install.sh                                   ← Linux/macOS one-liner bootstrap
├── collector/
│   └── browser-history-monitor.py              ← Python collector (Win/Linux/macOS)
├── installers/
│   ├── windows-installer.ps1                   ← Windows full installer (VT-clean)
│   ├── linux-installer.sh                      ← Linux installer (systemd user svc)
│   └── macos-installer.sh                      ← macOS installer (LaunchAgent)
└── wazuh/
    ├── decoders/
    │   └── 0310-browser_history_decoder.xml    ← Wazuh decoder
    └── rules/
        └── 0310-browser_history_rules.xml      ← 14 detection rules (MITRE mapped)
```

---

> **IT Fortress SOC** | Built by [Ram Kumar G](https://github.com/Ramkumar2545) | Wazuh v4.x | April 2026  
> VirusTotal-clean · No EXE downloads · No third-party URLs · MIT License
