#!/usr/bin/env python3
"""
Log Analysis & Suspicious Activity Detector
Author: Your Name
Description: Analyzes Windows and Linux system logs to detect
             suspicious activity and generate SOC-style incident reports.
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

from linux_parser import LinuxLogParser
from windows_parser import WindowsEventParser
from detectors import ThreatDetector
from report_generator import ReportGenerator


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Log Analysis & Suspicious Activity Detection Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--type", choices=["linux", "windows"], required=True,
                        help="Log type: 'linux' (auth.log) or 'windows' (CSV export)")
    parser.add_argument("--file", required=True,
                        help="Path to log file")
    parser.add_argument("--detect",
                        choices=["bruteforce", "privesc", "newuser", "all"],
                        default="all",
                        help="Detection type (default: all)")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Failed login threshold for brute force (default: 5)")
    parser.add_argument("--report",
                        help="Save incident report to specified file")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed output")
    return parser.parse_args()


def main():
    args = parse_arguments()

    log_file = Path(args.file)
    if not log_file.exists():
        print(f"[!] Error: File not found: {args.file}")
        sys.exit(1)

    print("=" * 65)
    print("   Log Analysis & Suspicious Activity Detector")
    print("=" * 65)
    print(f"[*] Log Type  : {args.type.upper()}")
    print(f"[*] File      : {args.file}")
    print(f"[*] Detection : {args.detect}")
    print(f"[*] Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 65)

    # Parse logs
    if args.type == "linux":
        parser = LinuxLogParser(args.file)
    else:
        parser = WindowsEventParser(args.file)

    events = parser.parse()
    print(f"[*] Parsed {len(events)} log events")

    # Run detection rules
    detector = ThreatDetector(events, threshold=args.threshold)
    findings = detector.run(detect_type=args.detect)

    # Display findings
    print(f"\n[!] FINDINGS ({len(findings)} alerts)")
    print("-" * 65)

    if not findings:
        print("[*] No suspicious activity detected.")
    else:
        for i, finding in enumerate(findings, 1):
            severity_color = {
                "CRITICAL": "\033[91m",
                "HIGH":     "\033[93m",
                "MEDIUM":   "\033[96m",
                "LOW":      "\033[92m",
            }.get(finding.get("severity", "LOW"), "")
            reset = "\033[0m"

            print(f"\n  [{i}] {severity_color}[{finding['severity']}]{reset} {finding['title']}")
            print(f"      Type     : {finding['type']}")
            print(f"      Detail   : {finding['detail']}")
            print(f"      IOCs     : {', '.join(finding.get('iocs', []))}")
            if args.verbose and finding.get("raw_events"):
                print(f"      Events   :")
                for event in finding["raw_events"][:5]:
                    print(f"               {event}")

    print("\n" + "=" * 65)

    # Generate report
    if args.report:
        generator = ReportGenerator(findings, args.file, args.type)
        generator.save(args.report)
        print(f"[*] Incident report saved: {args.report}")


if __name__ == "__main__":
    main()
