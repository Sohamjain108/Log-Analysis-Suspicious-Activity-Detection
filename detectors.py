#!/usr/bin/env python3
"""
Threat Detection Rules Engine
Implements detection logic for common attack patterns in log data.
"""

from collections import defaultdict, Counter
from datetime import datetime


class ThreatDetector:
    """
    Rule-based threat detection engine.

    Detects:
    - Brute force attacks (repeated failed logins from same IP)
    - Privilege escalation (sudo, group changes, new admin accounts)
    - New user creation (potential backdoor accounts)
    - Successful login after brute force (compromise indicator)
    - Suspicious process execution (Windows)
    - After-hours activity
    """

    def __init__(self, events: list, threshold: int = 5):
        self.events = events
        self.threshold = threshold
        self.findings = []

    def run(self, detect_type: str = "all") -> list:
        """Run all or specific detection rules."""
        self.findings = []

        if detect_type in ("all", "bruteforce"):
            self._detect_brute_force()
            self._detect_successful_after_brute_force()

        if detect_type in ("all", "privesc"):
            self._detect_privilege_escalation()
            self._detect_suspicious_sudo()

        if detect_type in ("all", "newuser"):
            self._detect_new_user_creation()

        # Windows-specific
        self._detect_suspicious_processes()
        self._detect_new_service_installation()

        return sorted(self.findings,
                      key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
                      .get(x["severity"], 4))

    # ─────────────────────────────────────────
    #  Detection Rules
    # ─────────────────────────────────────────

    def _detect_brute_force(self):
        """
        Detect brute force: >= threshold failed logins from same IP.
        """
        failed_by_ip = defaultdict(list)

        for event in self.events:
            if event.get("event_type") in ("failed_login", "invalid_user", "windows_4625"):
                ip = event.get("source_ip", "unknown")
                failed_by_ip[ip].append(event)

        for ip, events in failed_by_ip.items():
            if len(events) >= self.threshold:
                # Get targeted usernames
                users = list(set(e.get("user", "") for e in events))
                self.findings.append({
                    "title": f"Brute Force Attack Detected from {ip}",
                    "type": "Brute Force / Credential Stuffing",
                    "severity": "HIGH" if len(events) < 50 else "CRITICAL",
                    "detail": (
                        f"{len(events)} failed login attempts from {ip}. "
                        f"Targeted accounts: {', '.join(users[:5])}."
                    ),
                    "iocs": [ip] + users[:3],
                    "raw_events": [e.get("raw", "") for e in events[:10]],
                    "mitre": "T1110 — Brute Force"
                })

    def _detect_successful_after_brute_force(self):
        """
        Detect successful login from an IP that previously had many failures.
        Strong indicator of successful compromise.
        """
        failed_ips = defaultdict(int)
        success_events = []

        for event in self.events:
            if event.get("event_type") in ("failed_login", "invalid_user", "windows_4625"):
                failed_ips[event.get("source_ip", "")] += 1
            elif event.get("event_type") in ("accepted_login", "windows_4624"):
                success_events.append(event)

        for event in success_events:
            ip = event.get("source_ip", "")
            if failed_ips.get(ip, 0) >= self.threshold:
                self.findings.append({
                    "title": f"Successful Login After Brute Force from {ip}",
                    "type": "Possible Account Compromise",
                    "severity": "CRITICAL",
                    "detail": (
                        f"IP {ip} had {failed_ips[ip]} failed attempts followed by "
                        f"a successful login for user '{event.get('user', 'unknown')}'. "
                        f"This is a strong indicator of account compromise."
                    ),
                    "iocs": [ip, event.get("user", "")],
                    "raw_events": [event.get("raw", "")],
                    "mitre": "T1078 — Valid Accounts"
                })

    def _detect_privilege_escalation(self):
        """
        Detect user added to privileged group (sudo, wheel, admin, root).
        """
        priv_groups = {"sudo", "wheel", "admin", "root", "administrators",
                       "domain admins", "enterprise admins"}

        for event in self.events:
            etype = event.get("event_type", "")
            if etype in ("user_added_group", "windows_4732"):
                group = event.get("source_ip", "").lower()  # re-used field
                user = event.get("user", "unknown")
                if any(pg in group for pg in priv_groups):
                    self.findings.append({
                        "title": f"Privilege Escalation: {user} added to {group}",
                        "type": "Privilege Escalation",
                        "severity": "HIGH",
                        "detail": (
                            f"User '{user}' was added to privileged group '{group}'. "
                            f"Verify this change was authorized."
                        ),
                        "iocs": [user, group],
                        "raw_events": [event.get("raw", "")],
                        "mitre": "T1078.003 — Local Accounts"
                    })

    def _detect_suspicious_sudo(self):
        """
        Detect suspicious sudo commands (shell spawning, file modification).
        """
        suspicious_cmds = [
            "/bin/bash", "/bin/sh", "chmod 777", "wget", "curl",
            "/etc/passwd", "/etc/shadow", "nc ", "ncat", "python -c",
            "perl -e", "ruby -e", "base64 -d"
        ]

        for event in self.events:
            if event.get("event_type") == "sudo_command":
                cmd = event.get("command", "").lower()
                for susp in suspicious_cmds:
                    if susp in cmd:
                        self.findings.append({
                            "title": f"Suspicious sudo Command by {event.get('user')}",
                            "type": "Suspicious Command Execution",
                            "severity": "HIGH",
                            "detail": f"User '{event.get('user')}' ran: sudo {event.get('command', '')}",
                            "iocs": [event.get("user", ""), cmd],
                            "raw_events": [event.get("raw", "")],
                            "mitre": "T1059 — Command and Scripting Interpreter"
                        })
                        break

    def _detect_new_user_creation(self):
        """Detect new user account creation (potential backdoor)."""
        for event in self.events:
            if event.get("event_type") in ("new_user", "windows_4720"):
                user = event.get("user", "unknown")
                self.findings.append({
                    "title": f"New User Account Created: {user}",
                    "type": "Account Manipulation",
                    "severity": "MEDIUM",
                    "detail": (
                        f"A new user account '{user}' was created at {event.get('timestamp')}. "
                        f"Verify this was an authorized action."
                    ),
                    "iocs": [user],
                    "raw_events": [event.get("raw", "")],
                    "mitre": "T1136 — Create Account"
                })

    def _detect_suspicious_processes(self):
        """Detect suspicious process execution (Windows Event 4688)."""
        for event in self.events:
            if event.get("event_type") == "windows_4688" and event.get("suspicious_process"):
                proc = event.get("process", "unknown")
                self.findings.append({
                    "title": f"Suspicious Process Execution: {proc.split('\\')[-1]}",
                    "type": "Suspicious Process",
                    "severity": "MEDIUM",
                    "detail": f"Process '{proc}' executed by '{event.get('user')}' at {event.get('timestamp')}",
                    "iocs": [proc, event.get("user", "")],
                    "raw_events": [event.get("raw", "")],
                    "mitre": "T1059 — Command and Scripting Interpreter"
                })

    def _detect_new_service_installation(self):
        """Detect new service installation (Windows Event 7045) — common malware persistence."""
        for event in self.events:
            if event.get("event_type") == "windows_7045":
                self.findings.append({
                    "title": "New Windows Service Installed",
                    "type": "Persistence Mechanism",
                    "severity": "CRITICAL",
                    "detail": (
                        f"A new service was installed at {event.get('timestamp')}. "
                        f"This is a common malware persistence technique. Investigate immediately."
                    ),
                    "iocs": [event.get("user", "")],
                    "raw_events": [event.get("raw", "")],
                    "mitre": "T1543.003 — Create or Modify System Process: Windows Service"
                })
