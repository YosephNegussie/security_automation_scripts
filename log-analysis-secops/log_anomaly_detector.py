#!/usr/bin/env python3
"""
.SYNOPSIS
    Log Anomaly & SecOps Threat Detector
.DESCRIPTION
    Parses log files (such as web server access logs or authentication logs) 
    to detect brute-force patterns, suspicious status codes, and traffic anomalies.
    Satisfies ISO/IEC 27001 Logging and Monitoring control requirements.
.AUTHOR
    Yoseph Negussie Alula, MSc | BSI ISO/IEC 27001 Lead Auditor
"""

import os
import sys
import re
from collections import Counter
from datetime import datetime

def analyze_logs(log_file_path, threshold_requests=50, report_path="SecOps_Anomaly_Report.html"):
    print("========================================================")
    print("   Starting SecOps Log Anomaly Analysis...              ")
    print("========================================================")

    if not os.path.exists(log_file_path):
        print(f"[!] Error: Log file not found at '{log_file_path}'.")
        sys.exit(1)

    print(f"[*] Reading log file: {log_file_path}...")
    
    ip_counter = Counter()
    status_counter = Counter()
    suspicious_entries = []
    total_lines = 0

    # Common Apache/Nginx Combined Log Format Regex:
    # IP - - [Date] "METHOD URL PROTOCOL" Status Bytes
    log_pattern = re.compile(
        r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+-\s+\[(?P<date>[^\]]+)\]\s+"(?P<request>[^"]+)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)'
    )

    try:
        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                total_lines += 1
                match = log_pattern.match(line.strip())
                if match:
                    data = match.groupdict()
                    ip = data['ip']
                    status = data['status']
                    request = data['request']

                    ip_counter[ip] += 1
                    status_counter[status] += 1

                    # Flag potential web attacks (e.g., SQL Injection strings, Path Traversal, or 401/403 errors)
                    if any(bad_term in request.lower() for bad_term in ['union select', '../', 'etc/passwd', 'eval(']):
                        suspicious_entries.append({
                            'ip': ip,
                            'date': data['date'],
                            'request': request,
                            'status': status,
                            'reason': 'Potential Injection / Attack Signature Detected'
                        })
                    elif status in ['401', '403', '500']:
                        suspicious_entries.append({
                            'ip': ip,
                            'date': data['date'],
                            'request': request,
                            'status': status,
                            'reason': f'HTTP Error Status {status}'
                        })
    except Exception as e:
        print(f"[!] An error occurred while parsing the log: {e}")
        sys.exit(1)

    print(f"[+] Parsed {total_lines} log entries successfully.")

    # Check for Brute-Force / High-Frequency IPs exceeding threshold
    brute_force_ips = [ip for ip, count in ip_counter.items() if count > threshold_requests]
    for ip in brute_force_ips:
        suspicious_entries.append({
            'ip': ip,
            'date': 'Multiple / Continuous',
            'request': f'High Request Volume ({ip_counter[ip]} requests)',
            'status': 'N/A',
            'reason': 'Potential Brute-Force or Automated Scraping'
        })

    # Generate HTML Report
    generate_html_report(log_file_path, total_lines, ip_counter, status_counter, suspicious_entries, report_path)

def generate_html_report(source_file, total_lines, ip_counter, status_counter, anomalies, report_path):
    total_anomalies = len(anomalies)

    if total_anomalies == 0:
        health_status = "<span style='color: #27ae60; font-weight: bold;'>SECURE: No log anomalies or attack signatures detected.</span>"
    else:
        health_status = f"<span style='color: #c0392b; font-weight: bold;'>ACTION REQUIRED: {total_anomalies} potential anomaly/anomalies flagged for review.</span>"

    top_ips_rows = "".join([f"<tr><td>{ip}</td><td>{count} requests</td></tr>" for ip, count in ip_counter.most_common(5)])
    
    anomaly_rows = ""
    if anomalies:
        for item in anomalies:
            anomaly_rows += f"<tr><td>{item['ip']}</td><td>{item['date']}</td><td><code>{item['request']}</code></td><td>{item['status']}</td><td><b>{item['reason']}</b></td></tr>"
    else:
        anomaly_rows = "<tr><td colspan='5' style='text-align: center; color: #7f8c8d;'>No suspicious anomalies recorded in this sample.</td></tr>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SecOps Log Anomaly Analysis Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #f8f9fa; color: #2c3e50; margin: 30px; line-height: 1.6; }}
        .container {{ max-width: 1100px; margin: auto; background: #ffffff; padding: 30px; border-radius: 8px; border: 1px solid #e1e8ed; box-shadow: 0 4px 10px rgba(0,0,0,0.03); }}
        h2 {{ color: #0b192c; border-bottom: 2px solid #3498db; padding-bottom: 8px; margin-top: 0; text-transform: uppercase; font-size: 1.4rem; letter-spacing: 0.5px; }}
        h3 {{ color: #0b192c; margin-top: 25px; font-size: 1.1rem; }}
        .summary-box {{ background: #f1f6fb; border-left: 4px solid #3498db; padding: 15px 20px; margin: 20px 0; border-radius: 2px; font-size: 0.95rem; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th {{ background-color: #0b192c; color: #ffffff; text-align: left; padding: 10px; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px; }}
        td {{ padding: 10px; border-bottom: 1px solid #e1e8ed; font-size: 0.85rem; vertical-align: top; }}
        tr:nth-child(even) {{ background-color: #fdfdfd; }}
        tr:hover {{ background-color: #f4f6f9; }}
        .footer {{ margin-top: 30px; font-size: 0.8rem; color: #7f8c8d; text-align: center; border-top: 1px solid #e1e8ed; padding-top: 15px; }}
        code {{ background: #eee; padding: 2px 5px; border-radius: 3px; font-family: monospace; }}
    </style>
</head>
<body>
<div class="container">
    <h2>SecOps Log Anomaly & Threat Report</h2>
    <div class="summary-box">
        <strong>Executive Overview:</strong> {health_status}<br>
        <strong>Lead Analyst:</strong> Yoseph Negussie Alula, MSc (BSI ISO/IEC 27001 Lead Auditor)<br>
        <strong>Source Log File:</strong> {source_file}<br>
        <strong>Total Log Lines Processed:</strong> {total_lines}<br>
        <strong>Date Generated:</strong> {datetime.now().strftime('%B %d, %Y - HH:mm')}<br>
        <strong>Standard Alignment:</strong> ISO/IEC 27001:2022 (Logging, Monitoring & Incident Management)
    </div>

    <h3>Top Active Source IP Addresses</h3>
    <table>
        <tr><th>IP Address</th><th>Request Count</th></tr>
        {top_ips_rows if top_ips_rows else "<tr><td colspan='2'>No traffic recorded.</td></tr>"}
    </table>

    <h3>Flagged Anomalies & Suspicious Indicators</h3>
    <table>
        <tr><th>Source IP</th><th>Timestamp</th><th>Request Payload</th><th>Status</th><th>Detection Reason</th></tr>
        {anomaly_rows}
    </table>

    <div class="footer">
        Generated automatically via Security Automation Scripts | OmniStackIT
    </div>
</div>
</body>
</html>
"""

    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print("========================================================")
    print(f"   Analysis complete! Report generated at:              ")
    print(f"   -> {report_path}")
    print("========================================================")

if __name__ == "__main__":
    # Example execution: python log_anomaly_detector.py server_access.log
    target_log = sys.argv[1] if len(sys.argv) > 1 else "sample_access.log"
    analyze_logs(target_log)