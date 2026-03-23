#!/usr/bin/env python3
"""
Linux Auth Log Parser
Parses /var/log/auth.log and similar Linux authentication logs.
"""

import re
from datetime import datetime


class LinuxLogParser:
    """Parse Linux auth.log / secure log files."""

    # Regex patterns for common auth.log events
    PATTERNS = {
        "failed_login":   re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for (?:invalid user )?(\S+) from (\S+)"
        ),
        "accepted_login": re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+).*Accepted (?:password|publickey) for (\S+) from (\S+)"
        ),
        "sudo_command":   re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+).*sudo:.*?(\S+)\s+:.*COMMAND=(.*)"
        ),
        "new_user":       re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+).*(?:useradd|adduser).*'?(\S+)'?"
        ),
        "user_added_group": re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+).*usermod.*-G\s+(\S+)\s+(\S+)"
        ),
        "ssh_disconnect": re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+).*Disconnected from (?:invalid user )?(\S+) (\S+)"
        ),
        "invalid_user":   re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+).*Invalid user (\S+) from (\S+)"
        ),
    }

    def __init__(self, filepath: str):
        self.filepath = filepath

    def parse(self) -> list:
        """
        Parse log file and return structured events.

        Returns:
            List of event dicts: {timestamp, event_type, user, source_ip, raw}
        """
        events = []

        with open(self.filepath, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                event = self._parse_line(line)
                if event:
                    events.append(event)

        return events

    def _parse_line(self, line: str) -> dict | None:
        """Try all patterns against a log line."""

        for event_type, pattern in self.PATTERNS.items():
            match = pattern.search(line)
            if match:
                groups = match.groups()
                event = {
                    "timestamp": groups[0] if groups else "",
                    "event_type": event_type,
                    "user": groups[1] if len(groups) > 1 else "",
                    "source_ip": groups[2] if len(groups) > 2 else "",
                    "raw": line
                }

                # Extra data for sudo
                if event_type == "sudo_command" and len(groups) > 2:
                    event["command"] = groups[2]

                return event

        return None
