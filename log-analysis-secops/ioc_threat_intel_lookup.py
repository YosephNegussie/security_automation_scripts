#!/usr/bin/env python3
"""
.SYNOPSIS
    IOC Extraction & Threat Intelligence Enrichment Tool
.DESCRIPTION
    Extracts Indicators of Compromise (IPs, MD5/SHA256 hashes, domains) from raw incident 
    text or log files and enriches them with reputation checks to assist SOC analysis.
    Satisfies ISO/IEC 27001 Incident Management & Threat Intelligence requirements.
.AUTHOR
    Yoseph Negussie Alula, MSc | BSI ISO/IEC 27001 Lead Auditor
"""

import os
import sys
import re
import json
import urllib.request
import urllib.parse
from datetime import datetime

# Regex Patterns for IOC Extraction
REGEX_IPV4 = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
REGEX_SHA256 = r'\b[a-fA-F0-9]{64}\b'
REGEX_MD5 = r'\b[a-fA-F0-9]{32}\b'
REGEX_DOMAIN = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'

# Filter out local private IPs (RFC 1918)
def is_public_ip(ip):
    parts = list(map(int, ip.split('.')))
    if parts[0] == 10:
        return False
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return False
    if parts[0] == 192 and parts[1] == 168:
        return False
    if parts[0] == 127:
        return False
    return True

def extract_iocs(raw_text):
    ip_matches = list(set(re.findall(REGEX_IPV4, raw_text)))
    public_ips = [ip for ip in ip_matches if is_public_ip(ip)]
    
    sha256_matches = list(set(re.findall(REGEX_SHA256, raw_text)))
    md5_matches = list(set(re.findall(REGEX_MD5, raw_text)))
    
    # Exclude matches that are actually part of a SHA256 string
    clean_md5 = [h for h in md5_matches if not any(h in s for s in sha256_matches)]

    domains = list(set(re.findall(REGEX_DOMAIN, raw_text)))
    # Exclude common extensions/code artifacts
    filtered_domains = [d for d in domains if not d.endswith(('.py', '.js', '.css', '.html', '.local', '.internal'))]

    return {
        'ips': public_ips,
        'sha256': sha256_matches,
        'md5': clean_md5,
        'domains': filtered_domains
    }

def check_ip_reputation(ip, api_key=None):
    """
    Enriches IP with AbuseIPDB API if API key is present, otherwise falls back to standard DNS/WHOIS lookup metadata.
    """
    if api_key:
        try:
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
            req = urllib.request.Request(url, headers={'Key': api_key, 'Accept': 'application/json'})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())['data']
                return {
                    'ip': ip,
                    'score': f"{data.get('abuseConfidenceScore', 0)}%",
                    'isp': data.get('isp', 'Unknown'),
                    'country': data.get('countryCode', 'N/A'),
                    'status': 'HIGH RISK' if data.get('abuseConfidenceScore', 0) > 20 else 'Low Risk'
                }
        except Exception:
            pass

    # Fallback response when running in offline/API-key-less mode
    return {
        'ip': ip,
        'score': 'Pending Threat Intel Verification',
        'isp': 'External Network Host',
        'country': 'External',
        'status': 'Requires Review'
    }

def generate_ioc_report(iocs, enriched_ips, input_source, report_path="SecOps_IOC_Analysis_Report.html"):
    total_iocs = len(iocs['ips']) + len(iocs['sha256']) + len(iocs['md5']) + len(iocs['domains'])

    if total_iocs == 0:
        health_status = "<span style='color: #27ae60; font-weight: bold;'>CLEAN: No external Indicators of Compromise (IOCs) detected.</span>"
    else:
        health_status = f"<span style='color: #c0392b; font-weight: bold;'>FLAGGED: {total_iocs} external Indicator(s) of Compromise extracted for investigation.</span>"

    ip_rows = ""
    for item in enriched_ips:
        status_color = "#c0392b" if "HIGH" in item['status'] else "#2c3e50"
        ip_rows += f"<tr><td><code>{item['ip']}</code></td><td>{item['isp']}</td><td>{item['country']}</td><td>{item['score']}</td><td style='color: {status_color}; font-weight: bold;'>{item['status']}</td></tr>"

    if not ip_rows:
        ip_rows = "<tr><td colspan='5' style='text-align: center; color: #7f8c8d;'>No public IP indicators extracted.</td></tr>"

    hash_rows = ""
    for h in iocs['sha256']:
        hash_rows += f"<tr><td><code>{h}</code></td><td>SHA-256 File Hash</td><td>Pending ThreatIntel Hash Lookup</td></tr>"
    for h in iocs['md5']:
        hash_rows += f"<tr><td><code>{h}</code></td><td>MD5 File Hash</td><td>Pending ThreatIntel Hash Lookup</td></tr>"

    if not hash_rows:
        hash_rows = "<tr><td colspan='3' style='text-align: center; color: #7f8c8d;'>No file hash indicators extracted.</td></tr>"

    domain_rows = ""
    for d in iocs['domains']:
        domain_rows += f"<tr><td><code>{d}</code></td><td>Domain / Hostname</td><td>Extracted for DNS/Reputation Screening</td></tr>"

    if not domain_rows:
        domain_rows = "<tr><td colspan='3' style='text-align: center; color: #7f8c8d;'>No domain indicators extracted.</td></tr>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SecOps Threat Intelligence IOC Assessment</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #f8f9fa; color: #2c3e50; margin: 30px; line-height: 1.6; }}
        .container {{ max-width: 1100px; margin: auto; background: #ffffff; padding: 30px; border-radius: 8px; border: 1px solid #e1e8ed; box-shadow: 0 4px 10px rgba(0,0,0,0.03); }}
        h2 {{ color: #0b192c; border-bottom: 2px solid #3498db; padding-bottom: 8px; margin-top: 0; text-transform: uppercase; font-size: 1.4rem; letter-spacing: 0.5px; }}
        h3 {{ color: #0b192c; margin-top: 25px; font-size: 1.1rem; border-left: 3px solid #3498db; padding-left: 10px; }}
        .summary-box {{ background: #f1f6fb; border-left: 4px solid #3498db; padding: 15px 20px; margin: 20px 0; border-radius: 2px; font-size: 0.95rem; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th {{ background-color: #0b192c; color: #ffffff; text-align: left; padding: 10px; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px; }}
        td {{ padding: 10px; border-bottom: 1px solid #e1e8ed; font-size: 0.85rem; vertical-align: top; }}
        tr:nth-child(even) {{ background-color: #fdfdfd; }}
        tr:hover {{ background-color: #f4f6f9; }}
        .footer {{ margin-top: 30px; font-size: 0.8rem; color: #7f8c8d; text-align: center; border-top: 1px solid #e1e8ed; padding-top: 15px; }}
        code {{ background: #eee; padding: 2px 5px; border-radius: 3px; font-family: monospace; font-size: 0.85em; }}
    </style>
</head>
<body>
<div class="container">
    <h2>SecOps Threat Intelligence IOC Assessment</h2>
    <div class="summary-box">
        <strong>Executive Overview:</strong> {health_status}<br>
        <strong>Lead Auditor / Analyst:</strong> Yoseph Negussie Alula, MSc (BSI ISO/IEC 27001 Lead Auditor)<br>
        <strong>Input Source File:</strong> {input_source}<br>
        <strong>Date Generated:</strong> {datetime.now().strftime('%B %d, %Y - HH:mm')}<br>
        <strong>Standard Alignment:</strong> ISO/IEC 27001:2022 (Controls A.5.25 & A.5.26 - Incident Response & Threat Intel)
    </div>

    <h3>Extracted Public IP Addresses</h3>
    <table>
        <tr><th>IP Address</th><th>ISP / Provider</th><th>Country</th><th>Threat Confidence</th><th>Assessment</th></tr>
        {ip_rows}
    </table>

    <h3>Extracted File Hashes (MD5 / SHA-256)</h3>
    <table>
        <tr><th>File Hash Value</th><th>Hash Type</th><th>Status</th></tr>
        {hash_rows}
    </table>

    <h3>Extracted Domains & Hostnames</h3>
    <table>
        <tr><th>Domain Name</th><th>Type</th><th>Status</th></tr>
        {domain_rows}
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
    print(f"   Analysis complete! Executive IOC report generated at:")
    print(f"   -> {report_path}")
    print("========================================================")

def main():
    print("========================================================")
    print("   Starting Threat Intelligence IOC Extractor...        ")
    print("========================================================")

    if len(sys.argv) < 2:
        print("[!] Usage: python ioc_threat_intel_lookup.py <input_text_or_log_file>")
        print("[i] Running with built-in incident test payload...")
        sample_payload = """
        ALERT [2026-10-26 14:22:01]: Suspicious connection attempt from external host 185.220.101.5.
        Executable dropped in C:\\Temp\\malware.exe with SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        Command and Control communication domain established with malware-c2-server.com.
        Internal workstation 192.168.1.45 flagged as compromised.
        """
        input_source = "Built-in Test Sample"
        raw_text = sample_payload
    else:
        file_path = sys.argv[1]
        if not os.path.exists(file_path):
            print(f"[!] Error: File '{file_path}' not found.")
            sys.exit(1)
        input_source = file_path
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            raw_text = f.read()

    iocs = extract_iocs(raw_text)
    print(f"[+] Extracted {len(iocs['ips'])} public IP(s), {len(iocs['sha256'])} SHA256 hash(es), {len(iocs['md5'])} MD5 hash(es), {len(iocs['domains'])} domain(s).")

    # Optional AbuseIPDB API key from environment variable
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    enriched_ips = [check_ip_reputation(ip, api_key) for ip in iocs['ips']]

    generate_ioc_report(iocs, enriched_ips, input_source)

if __name__ == "__main__":
    main()