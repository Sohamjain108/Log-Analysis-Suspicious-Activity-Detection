#!/usr/bin/env python3
"""
Windows Event Log Parser
Parses CSV exports from Windows Event Viewer.
"""

import csv
import re
from datetime import datetime


# Key Windows Security Event IDs and their meaning
WINDOWS_EVENT_IDS = {
    4624: {"name": "Logon Success",         "severity": "LOW"},
    4625: {"name": "Logon Failure",          "severity": "MEDIUM"},
    4634: {"name": "Logoff",                 "severity": "LOW"},
    4648: {"name": "Explicit Cred Logon",    "severity": "HIGH"},
    4672: {"name": "Special Privileges",     "severity": "MEDIUM"},
    4688: {"name": "Process Created",        "severity": "MEDIUM"},
    4698: {"name": "Scheduled Task Created", "severity": "HIGH"},
    4719: {"name": "Audit Policy Changed",   "severity": "HIGH"},
    4720: {"name": "User Account Created",   "severity": "HIGH"},
    4726: {"name": "User Account Deleted",   "severity": "HIGH"},
    4732: {"name": "User Added to Group",    "severity": "HIGH"},
    4740: {"name": "Account Locked Out",     "severity": "MEDIUM"},
    7036: {"name": "Service State Changed",  "severity": "LOW"},
    7045: {"name": "New Service Installed",  "severity": "CRITICAL"},
}

SUSPICIOUS_PROCESSES = [
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "bitsadmin.exe", "net.exe", "net1.exe", "whoami.exe",
    "mimikatz.exe", "psexec.exe", "wmic.exe"
]


class WindowsEventParser:
    """Parse Windows Event Log CSV exports."""

    def __init__(self, filepath: str):
        self.filepath = filepath

    def parse(self) -> list:
        """
        Parse Windows Event Log CSV export.

        CSV format expected (from Event Viewer export):
            Level,Date and Time,Source,Event ID,Task Category,Description

        Returns:
            List of structured event dicts
        """
        events = []

        try:
            with open(self.filepath, "r", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    event = self._normalize_row(row)
                    if event:
                        events.append(event)
        except Exception as e:
            print(f"[!] Error parsing Windows log: {e}")

        return events

    def _normalize_row(self, row: dict) -> dict | None:
        """Normalize a CSV row into a standard event dict."""
        try:
            # Handle different CSV column name formats
            event_id = int(
                row.get("Event ID", row.get("EventID", row.get("Id", 0)))
            )
            timestamp = row.get("Date and Time", row.get("TimeCreated", ""))
            description = row.get("Description", row.get("Message", ""))
            source = row.get("Source", row.get("ProviderName", ""))

            # Extract username from description (heuristic)
            user = self._extract_field(description, [
                r"Account Name:\s+(\S+)",
                r"Subject:\s+.*?Account Name:\s+(\S+)",
                r"New Logon:.*?Account Name:\s+(\S+)",
            ])

            # Extract source IP from description
            source_ip = self._extract_field(description, [
                r"Source Network Address:\s+(\S+)",
                r"Workstation Name:\s+(\S+)",
            ])

            # Extract process name for 4688
            process = self._extract_field(description, [
                r"New Process Name:\s+(.+)",
                r"Process Name:\s+(.+)",
            ])

            event_info = WINDOWS_EVENT_IDS.get(event_id, {
                "name": "Unknown", "severity": "LOW"
            })

            # Flag suspicious processes
            is_suspicious_proc = False
            if process:
                proc_lower = process.lower()
                is_suspicious_proc = any(sp in proc_lower for sp in SUSPICIOUS_PROCESSES)

            return {
                "event_id": event_id,
                "event_name": event_info["name"],
                "severity": event_info["severity"],
                "timestamp": timestamp,
                "source": source,
                "user": user or "N/A",
                "source_ip": source_ip or "N/A",
                "process": process or "",
                "suspicious_process": is_suspicious_proc,
                "description": description[:200],  # truncate
                "event_type": f"windows_{event_id}",
                "raw": str(row)
            }

        except Exception:
            return None

    def _extract_field(self, text: str, patterns: list) -> str:
        """Try multiple regex patterns to extract a field."""
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1).strip()
        return ""
