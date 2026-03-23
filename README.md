# 📋 Project 3: Log Analysis & Suspicious Activity Detection

## Overview

Windows and Linux log analysis project simulating **Tier 1 SOC operations**. Analyzes system logs to detect anomalous patterns, correlate events, and identify Indicators of Compromise (IOCs) consistent with real-world security incidents.

---

## 🎯 Learning Objectives

- Parse and analyze Windows Event Logs and Linux syslog/auth.log
- Identify suspicious patterns: brute force, privilege escalation, lateral movement
- Practice event correlation and IOC identification
- Document findings in SOC-style incident reports
- Understand SIEM workflow simulation

---

## 🛠️ Tools Used

| Tool | Purpose |
|------|---------|
| Python (script) | Log parsing and pattern detection |
| Windows Event Viewer | GUI-based Windows log review |
| Splunk Free / ELK Stack | SIEM ingestion and querying |
| journalctl / grep / awk | Linux log analysis |
| Kali Linux | Testing environment |

---

## 📋 Key Windows Event IDs to Know

| Event ID | Description | Suspicious Context |
|----------|-------------|-------------------|
| 4624 | Successful logon | After hours, new account |
| 4625 | Failed logon | Repeated failures = brute force |
| 4634 | Logoff | |
| 4648 | Logon with explicit credentials | Pass-the-hash, runas |
| 4672 | Special privileges assigned | Admin rights assigned |
| 4688 | New process created | PowerShell, cmd, wscript |
| 4698 | Scheduled task created | Persistence mechanism |
| 4719 | Audit policy changed | Defense evasion |
| 4720 | User account created | Backdoor account |
| 4726 | User account deleted | Cover tracks |
| 4732 | User added to local group | Privilege escalation |
| 4740 | Account locked out | Brute force indicator |
| 7036 | Service stopped/started | Malware as service |
| 7045 | New service installed | Malware installation |

---

## 🐧 Key Linux Log Locations

| Log File | Contents |
|----------|---------|
| `/var/log/auth.log` | Authentication events (Debian/Ubuntu) |
| `/var/log/secure` | Authentication events (RHEL/CentOS) |
| `/var/log/syslog` | General system messages |
| `/var/log/kern.log` | Kernel messages |
| `/var/log/apache2/access.log` | Web server access |
| `/var/log/apache2/error.log` | Web server errors |
| `/var/log/fail2ban.log` | Fail2ban ban events |
| `/var/log/wtmp` | Login history (use `last`) |
| `/var/log/btmp` | Failed login history (use `lastb`) |

---

## 🚀 Running the Log Analyzer

```bash
cd 3-log-analysis-ids
pip3 install -r requirements.txt

# Analyze Linux auth logs
python3 src/log_analyzer.py --type linux --file logs/samples/sample_auth.log

# Analyze Windows Event Log export (CSV/XML)
python3 src/log_analyzer.py --type windows --file logs/samples/sample_windows_events.csv

# Detect brute force specifically
python3 src/log_analyzer.py --type linux --file logs/samples/sample_auth.log --detect bruteforce

# Generate incident report
python3 src/log_analyzer.py --type linux --file logs/samples/sample_auth.log --report output_report.md
```

---

## 🔍 Kali Linux Manual Log Commands

```bash
# Show all failed SSH logins
grep "Failed password" /var/log/auth.log

# Count failed logins per IP
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn

# Detect brute force (>10 failures)
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | awk '$1 > 10'

# Show successful logins after failures (compromise indicator)
grep "Accepted password" /var/log/auth.log

# Show all sudo commands (privilege escalation monitoring)
grep "sudo:" /var/log/auth.log

# View login history
last -a | head -20

# View failed login history  
sudo lastb | head -20

# Check for new users created
grep "useradd" /var/log/auth.log
grep "adduser" /var/log/auth.log
```

---

## 📁 Project Files

```
3-log-analysis-ids/
├── src/
│   ├── log_analyzer.py         # Main analyzer script
│   ├── windows_parser.py       # Windows Event Log parser
│   ├── linux_parser.py         # Linux auth/syslog parser
│   ├── detectors.py            # Detection rules engine
│   └── report_generator.py     # Incident report generator
├── logs/
│   └── samples/
│       ├── sample_auth.log     # Simulated Linux auth log
│       └── sample_windows_events.csv  # Simulated Windows events
├── docs/
│   └── soc_workflow_notes.md   # SOC Tier 1 workflow notes
├── requirements.txt
└── README.md
```
