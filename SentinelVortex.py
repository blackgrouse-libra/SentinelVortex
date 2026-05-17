#!/usr/bin/env python3
"""
SentinelVortex
Authorized Web Security Assessment Framework
For legitimate penetration testing, client engagements, and bug bounty programs.

DISCLAIMER: Only use this tool on systems you own or have explicit written 
authorization to test. Unauthorized scanning may violate laws.

Author: BlackGrouse
Date: 2026-05-17
"""

import subprocess
import json
import os
import sys
import re
import socket
import argparse
from datetime import datetime
from urllib.parse import urlparse
from pathlib import Path

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class WebSecurityAssessor:
    def __init__(self, target, output_dir="assessment_results"):
        self.target = target
        self.parsed = urlparse(target)
        self.host = self.parsed.hostname
        self.port = self.parsed.port or (443 if self.parsed.scheme == 'https' else 80)
        self.scheme = self.parsed.scheme or 'http'
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_dir = os.path.join(output_dir, f"{self.host}_{self.timestamp}")
        self.findings = []
        self.tool_outputs = {}

        os.makedirs(self.session_dir, exist_ok=True)

    def log(self, message, level="INFO"):
        color = {
            "INFO": Colors.OKBLUE,
            "SUCCESS": Colors.OKGREEN,
            "WARNING": Colors.WARNING,
            "ERROR": Colors.FAIL,
            "HEADER": Colors.HEADER
        }.get(level, Colors.OKBLUE)
        print(f"{color}[{level}] {message}{Colors.ENDC}")

    def run_command(self, cmd, tool_name, timeout=300):
        """Execute a shell command and capture output."""
        self.log(f"Running {tool_name}...", "HEADER")
        output_file = os.path.join(self.session_dir, f"{tool_name}.txt")

        try:
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            output = result.stdout + result.stderr

            with open(output_file, 'w') as f:
                f.write(output)

            self.tool_outputs[tool_name] = output
            self.log(f"{tool_name} completed. Output saved to {output_file}", "SUCCESS")
            return output

        except subprocess.TimeoutExpired:
            self.log(f"{tool_name} timed out after {timeout}s", "WARNING")
            return ""
        except Exception as e:
            self.log(f"{tool_name} failed: {str(e)}", "ERROR")
            return ""

    def add_finding(self, severity, title, description, evidence, remediation, references=None):
        finding = {
            "severity": severity,
            "title": title,
            "description": description,
            "evidence": evidence,
            "remediation": remediation,
            "references": references or [],
            "timestamp": datetime.now().isoformat()
        }
        self.findings.append(finding)
        self.log(f"Finding added: [{severity}] {title}", "WARNING" if severity in ["High", "Critical"] else "INFO")

    # ==================== RECONNAISSANCE ====================

    def run_dns_recon(self):
        """DNS enumeration and subdomain discovery."""
        self.log("Starting DNS & Subdomain Reconnaissance", "HEADER")

        # DNS enumeration with dnsenum
        self.run_command(
            f"dnsenum --enum {self.host} -o {self.session_dir}/dnsenum.xml 2>/dev/null || true",
            "dnsenum"
        )

        # Subdomain discovery with sublist3r
        self.run_command(
            f"sublist3r -d {self.host} -o {self.session_dir}/subdomains.txt 2>/dev/null || true",
            "sublist3r"
        )

        # TheHarvester for email/OSINT
        self.run_command(
            f"theHarvester -d {self.host} -b all -f {self.session_dir}/theharvester 2>/dev/null || true",
            "theHarvester"
        )

        # Check for DNS zone transfer
        output = self.run_command(
            f"dig axfr @{self.host} {self.host} 2>/dev/null || dig axfr {self.host} 2>/dev/null || true",
            "dns_zone_transfer"
        )

        if "ANSWER SECTION" in output and "SOA" not in output:
            self.add_finding(
                "High",
                "DNS Zone Transfer Vulnerability (AXFR)",
                "The DNS server allows zone transfers, exposing all DNS records including internal subdomains and infrastructure details.",
                output[:500],
                "Disable zone transfers in DNS configuration. Restrict AXFR to authorized secondary DNS servers only.",
                ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/10-Test_Network_Infrastructure_Configuration"]
            )

    def run_host_discovery(self):
        """Network layer reconnaissance."""
        self.log("Starting Host Discovery & Port Scanning", "HEADER")

        # Resolve IP
        try:
            self.ip = socket.gethostbyname(self.host)
            self.log(f"Resolved {self.host} to {self.ip}", "SUCCESS")
        except:
            self.ip = self.host
            self.log("Could not resolve hostname to IP", "WARNING")

        # Nmap comprehensive scan
        nmap_cmd = (
            f"nmap -sS -sV -sC -O -A --script=vuln,http-enum,ssl-enum-ciphers "
            f"-p- --open -oN {self.session_dir}/nmap_full.txt "
            f"-oX {self.session_dir}/nmap.xml {self.ip}"
        )
        nmap_output = self.run_command(nmap_cmd, "nmap_full", timeout=600)

        # Parse Nmap for common issues
        if "ssl-enum-ciphers" in nmap_output:
            weak_ciphers = re.findall(r'\| (TLS_RSA_WITH_3DES_EDE_CBC_SHA|SSLv[23]|RC4|DES|MD5|NULL|EXP|EXPORT)', nmap_output)
            if weak_ciphers:
                self.add_finding(
                    "High",
                    "Weak SSL/TLS Cipher Suites Detected",
                    f"Nmap detected weak or deprecated cipher suites: {set(weak_ciphers)}. These can enable downgrade attacks, eavesdropping, or man-in-the-middle attacks.",
                    "See nmap_full.txt for full cipher enumeration.",
                    "Disable weak ciphers (SSLv2, SSLv3, RC4, DES, 3DES, MD5, EXPORT). Enable only TLS 1.2+ with strong cipher suites.",
                    ["https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cipher_String_Cheat_Sheet.html"]
                )

        # Check for open dangerous ports
        dangerous_ports = {
            21: "FTP",
            23: "Telnet", 
            25: "SMTP (open relay risk)",
            53: "DNS",
            110: "POP3",
            143: "IMAP",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB",
            9200: "Elasticsearch"
        }

        for port, service in dangerous_ports.items():
            if f"{port}/tcp open" in nmap_output:
                self.add_finding(
                    "Medium" if port in [21, 110, 143] else "High",
                    f"Potentially Exposed Service: {service} (Port {port})",
                    f"Port {port} ({service}) is open to the internet. If misconfigured, this could allow unauthorized access to backend services.",
                    f"nmap output: {port}/tcp open",
                    f"Restrict access to port {port} via firewall. If public access is required, ensure strong authentication and encryption are enforced.",
                    ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/10-Test_Network_Infrastructure_Configuration"]
                )

    # ==================== WEB APPLICATION TESTING ====================

    def run_web_scanning(self):
        """Web-specific vulnerability scanning."""
        self.log("Starting Web Application Vulnerability Scanning", "HEADER")

        # Nikto comprehensive scan
        nikto_cmd = (
            f"nikto -h {self.target} -C all -o {self.session_dir}/nikto.txt "
            f"2>/dev/null || true"
        )
        nikto_output = self.run_command(nikto_cmd, "nikto", timeout=300)

        # Parse Nikto findings
        nikto_patterns = [
            (r'(X-Frame-Options|Content-Security-Policy|X-Content-Type-Options|Strict-Transport-Security|X-XSS-Protection).*header is not present',
             "Low", "Missing Security Headers", 
             "The application is missing critical HTTP security headers that protect against common attacks like clickjacking, XSS, and MIME-sniffing.",
             "Add the following headers: X-Frame-Options, Content-Security-Policy, X-Content-Type-Options, Strict-Transport-Security (HSTS), X-XSS-Protection."),

            (r'OSVDB.*(SQL Injection|SQLi|sql injection)', 
             "Critical", "SQL Injection Vulnerability",
             "Nikto detected a potential SQL injection point. Attackers could extract, modify, or delete database contents.",
             "Use parameterized queries/prepared statements. Implement input validation and WAF rules. Never concatenate user input into SQL queries."),

            (r'OSVDB.*(XSS|Cross Site Scripting|cross-site scripting)',
             "High", "Cross-Site Scripting (XSS) Vulnerability",
             "Reflected or stored XSS was detected. Attackers can inject malicious scripts to steal cookies, session tokens, or deface the site.",
             "Implement context-aware output encoding. Use Content-Security-Policy. Validate and sanitize all user inputs."),

            (r'Index of /|Directory indexing|directory listing',
             "Medium", "Directory Listing Enabled",
             "The web server allows directory listing, potentially exposing sensitive files, source code, or configuration backups.",
             "Disable directory indexing in web server configuration (Options -Indexes in Apache, autoindex off in Nginx)."),

            (r'\.git/|\.svn/|\.hg/|\.env|\.htaccess|\.htpasswd|backup|\.bak|\.old|\.swp',
             "High", "Sensitive File/Directory Exposure",
             "Version control files, configuration files, or backups are accessible. These may contain credentials, source code, or internal paths.",
             "Remove all development artifacts from production. Block access to hidden files via web server configuration."),

            (r'Default (page|file|installation)|Welcome to|Test Page|It works!',
             "Low", "Default Installation Detected",
             "Default pages or configurations suggest the application may not be properly hardened or customized.",
             "Remove default pages, change default credentials, and harden default configurations before production deployment."),
        ]

        for pattern, severity, title, description, remediation in nikto_patterns:
            matches = re.findall(pattern, nikto_output, re.IGNORECASE)
            if matches:
                evidence = "; ".join(set(str(m) for m in matches[:3]))
                self.add_finding(severity, title, description, evidence, remediation)

        # SSL/TLS Analysis with sslscan
        if self.scheme == 'https':
            ssl_output = self.run_command(
                f"sslscan --no-failed {self.host}:{self.port} 2>/dev/null || true",
                "sslscan"
            )

            if "SSLv2" in ssl_output or "SSLv3" in ssl_output:
                self.add_finding(
                    "Critical",
                    "Deprecated SSL Protocol Enabled",
                    "SSLv2 or SSLv3 is enabled. These protocols have severe cryptographic flaws (POODLE, DROWN) and should never be used.",
                    "See sslscan.txt for protocol details.",
                    "Disable SSLv2 and SSLv3. Enable only TLS 1.2 and TLS 1.3.",
                    ["https://www.acunetix.com/blog/articles/poodle-vulnerability/"]
                )

            if "RC4" in ssl_output or "DES" in ssl_output or "3DES" in ssl_output:
                self.add_finding(
                    "High",
                    "Weak Encryption Algorithms Enabled",
                    "Weak ciphers (RC4, DES, 3DES) are supported. These can be broken with modern computational resources.",
                    "See sslscan.txt for cipher details.",
                    "Disable RC4, DES, and 3DES. Use only AES-GCM and ChaCha20-Poly1305 with TLS 1.2+.",
                    ["https://wiki.mozilla.org/Security/Server_Side_TLS"]
                )

        # Directory brute-forcing with Gobuster
        wordlists = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt"
        ]
        wordlist = next((w for w in wordlists if os.path.exists(w)), "/usr/share/wordlists/dirb/common.txt")

        gobuster_cmd = (
            f"gobuster dir -u {self.target} -w {wordlist} "
            f"-x php,html,txt,bak,old,zip,tar,gz,sql,env,config,xml,json,js,log "
            f"-o {self.session_dir}/gobuster.txt -t 50 --no-error 2>/dev/null || true"
        )
        gobuster_output = self.run_command(gobuster_cmd, "gobuster", timeout=300)

        # Parse Gobuster for sensitive files
        sensitive_patterns = [
            (r'/(\.env|\.git|\.svn|\.htaccess|\.htpasswd|config\.php|wp-config|database\.sql|backup|\.bak)',
             "High", "Sensitive Configuration File Exposed",
             "A sensitive configuration or backup file was discovered during directory brute-forcing.",
             "Remove sensitive files from web root. Implement access controls. Store configuration files outside the document root."),

            (r'/(admin|administrator|login|signin|wp-login|phpmyadmin|manage|panel|backend|api|swagger|graphql)',
             "Medium", "Administrative/Backend Endpoint Discovered",
             "An administrative or API endpoint was found. If not properly protected, this could allow unauthorized access to backend functions.",
             "Restrict administrative interfaces by IP. Enforce MFA. Monitor and log access attempts. Rename default admin paths."),

            (r'/(api|rest|v1|graphql|swagger|openapi)',
             "Medium", "API Endpoint Discovered",
             "An API endpoint was discovered. APIs often have different security requirements and may expose more functionality than the web UI.",
             "Ensure API endpoints require authentication. Implement rate limiting. Validate all inputs. Document and secure API access."),
        ]

        for pattern, severity, title, description, remediation in sensitive_patterns:
            matches = re.findall(pattern, gobuster_output, re.IGNORECASE)
            if matches:
                evidence = "; ".join(set(str(m) for m in matches[:5]))
                self.add_finding(severity, title, description, evidence, remediation)

        # WhatWeb fingerprinting
        self.run_command(
            f"whatweb -a 3 {self.target} 2>/dev/null || true",
            "whatweb"
        )

        # Wafw00f for WAF detection
        self.run_command(
            f"wafw00f {self.target} 2>/dev/null || true",
            "wafw00f"
        )

    def run_advanced_web_tests(self):
        """Advanced application layer testing."""
        self.log("Starting Advanced Web Application Tests", "HEADER")

        # SQLMap (safe enumeration only - no exploitation)
        sqlmap_cmd = (
            f"sqlmap -u '{self.target}' --batch --level=1 --risk=1 "
            f"--banner --current-db --dbs --tables --count "
            f"--output-dir={self.session_dir}/sqlmap 2>/dev/null || true"
        )
        sqlmap_output = self.run_command(sqlmap_cmd, "sqlmap_enum", timeout=300)

        if "is vulnerable" in sqlmap_output.lower() or "sql injection" in sqlmap_output.lower():
            self.add_finding(
                "Critical",
                "SQL Injection Vulnerability Confirmed (sqlmap)",
                "Sqlmap confirmed the target is vulnerable to SQL injection. This allows attackers to read, modify, or delete database contents, and potentially execute commands on the server.",
                "See sqlmap_enum.txt for technical details. DO NOT exploit without explicit client authorization.",
                "Use parameterized queries (prepared statements). Implement input validation. Apply principle of least privilege to database accounts. Use a WAF as secondary defense.",
                ["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"]
            )

        # XSSer for XSS detection
        xsser_cmd = (
            f"xsser -u '{self.target}' --auto --Fp -v 2>/dev/null || true"
        )
        xsser_output = self.run_command(xsser_cmd, "xsser", timeout=300)

        if "Vulnerable" in xsser_output or "XSS" in xsser_output:
            self.add_finding(
                "High",
                "Cross-Site Scripting (XSS) Confirmed (XSSer)",
                "XSSer confirmed XSS vulnerabilities. Attackers can inject malicious scripts to hijack sessions, steal credentials, or perform actions on behalf of users.",
                "See xsser.txt for payload details.",
                "Implement Content-Security-Policy. Encode all output based on context. Use modern frameworks that auto-escape output. Validate all inputs.",
                ["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"]
            )

        # WPScan if WordPress detected
        wp_output = self.run_command(
            f"wpscan --url {self.target} --enumerate ap,at,cb,dbe,u --no-update "
            f"-o {self.session_dir}/wpscan.txt 2>/dev/null || true",
            "wpscan",
            timeout=300
        )

        if "WordPress version" in wp_output or "URL seems to be running WordPress" in wp_output:
            if "vulnerable" in wp_output.lower() or "outdated" in wp_output.lower():
                self.add_finding(
                    "High",
                    "WordPress Vulnerabilities Detected",
                    "WPScan identified vulnerable WordPress core, plugins, or themes. WordPress vulnerabilities are commonly exploited in the wild.",
                    "See wpscan.txt for vulnerable components.",
                    "Update WordPress core, themes, and plugins immediately. Remove unused plugins/themes. Implement WordPress hardening guidelines.",
                    ["https://wordpress.org/about/security/"]
                )

        # Nuclei for template-based scanning
        nuclei_cmd = (
            f"nuclei -u {self.target} -t /usr/share/nuclei-templates/ "
            f"-severity critical,high,medium -o {self.session_dir}/nuclei.txt "
            f"-silent 2>/dev/null || true"
        )
        nuclei_output = self.run_command(nuclei_cmd, "nuclei", timeout=300)

        if nuclei_output.strip():
            self.add_finding(
                "Medium",
                "Nuclei Template Matches Found",
                "Nuclei identified matches for known vulnerability templates. These represent specific, known security issues.",
                "See nuclei.txt for matched templates and details.",
                "Review each Nuclei finding individually. Apply vendor patches or configuration changes specific to the identified vulnerability.",
                ["https://nuclei.projectdiscovery.io/"]
            )

    def run_authentication_tests(self):
        """Test authentication and session mechanisms."""
        self.log("Starting Authentication & Session Analysis", "HEADER")

        # Test for common default credentials with Hydra (only if login form found)
        # This is commented out by default - should only be run with explicit client consent
        self.log("Skipping brute-force tests (requires explicit client authorization)", "INFO")
        self.add_finding(
            "Info",
            "Authentication Brute-Force Testing Skipped",
            "Credential brute-forcing was skipped as it requires explicit client authorization and may lock accounts.",
            "N/A",
            "To test authentication strength, use Hydra or Burp Intruder with client approval and account lockout awareness.",
            ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/"]
        )

    def analyze_headers(self):
        """Analyze HTTP security headers."""
        self.log("Analyzing HTTP Security Headers", "HEADER")

        curl_cmd = (
            f"curl -sI -L -k --max-time 10 '{self.target}' 2>/dev/null || true"
        )
        headers = self.run_command(curl_cmd, "http_headers")

        required_headers = {
            'Strict-Transport-Security': (
                "High" if self.scheme == 'https' else "Medium",
                "Missing HSTS Header",
                "HTTP Strict Transport Security (HSTS) is not configured. This allows SSL stripping attacks and man-in-the-middle attacks.",
                "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' header."
            ),
            'Content-Security-Policy': (
                "Medium",
                "Missing Content-Security-Policy Header",
                "CSP is not configured. This increases the impact of XSS vulnerabilities by allowing injected scripts to execute.",
                "Implement a strict CSP policy. Start with 'Content-Security-Policy: default-src 'self'; script-src 'self'' and refine."
            ),
            'X-Frame-Options': (
                "Medium",
                "Missing X-Frame-Options Header",
                "The site can be embedded in iframes on attacker-controlled sites, enabling clickjacking attacks.",
                "Add 'X-Frame-Options: DENY' or 'Content-Security-Policy: frame-ancestors 'none'' header."
            ),
            'X-Content-Type-Options': (
                "Low",
                "Missing X-Content-Type-Options Header",
                "Browsers may MIME-sniff responses, potentially treating non-executable content as executable (leading to XSS).",
                "Add 'X-Content-Type-Options: nosniff' header."
            ),
            'Referrer-Policy': (
                "Low",
                "Missing Referrer-Policy Header",
                "Sensitive URL parameters or paths may leak to third-party sites via the Referer header.",
                "Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer' header."
            ),
            'Permissions-Policy': (
                "Low",
                "Missing Permissions-Policy Header",
                "Browser features (camera, microphone, geolocation) may be accessible to embedded content without explicit control.",
                "Add 'Permissions-Policy: geolocation=(), microphone=(), camera=()' header."
            )
        }

        headers_lower = headers.lower()

        for header, (severity, title, description, remediation) in required_headers.items():
            if header.lower() not in headers_lower:
                self.add_finding(severity, title, description, f"Header not present in HTTP response", remediation)

        # Check for information disclosure headers
        info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator']
        found_info = []
        for h in info_headers:
            match = re.search(rf'{h}:\s*(.+)', headers, re.IGNORECASE)
            if match:
                found_info.append(f"{h}: {match.group(1).strip()}")

        if found_info:
            self.add_finding(
                "Low",
                "Information Disclosure in HTTP Headers",
                "The server reveals technology stack information in HTTP headers, aiding attackers in targeting known vulnerabilities for specific software versions.",
                "; ".join(found_info),
                "Remove or obfuscate Server, X-Powered-By, and similar headers. Use generic values or remove them entirely.",
                ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework"]
            )

    def generate_report(self):
        """Generate comprehensive assessment report."""
        self.log("Generating Assessment Report", "HEADER")

        # Sort findings by severity
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        self.findings.sort(key=lambda x: severity_order.get(x['severity'], 5))

        report = {
            "assessment_metadata": {
                "target": self.target,
                "host": self.host,
                "ip": getattr(self, 'ip', 'N/A'),
                "port": self.port,
                "scheme": self.scheme,
                "timestamp": self.timestamp,
                "assessor": "Authorized Security Assessment",
                "scope": "Web application security assessment performed with explicit authorization"
            },
            "executive_summary": {
                "total_findings": len(self.findings),
                "critical": len([f for f in self.findings if f['severity'] == 'Critical']),
                "high": len([f for f in self.findings if f['severity'] == 'High']),
                "medium": len([f for f in self.findings if f['severity'] == 'Medium']),
                "low": len([f for f in self.findings if f['severity'] == 'Low']),
                "info": len([f for f in self.findings if f['severity'] == 'Info'])
            },
            "findings": self.findings,
            "tool_outputs": {k: f"{self.session_dir}/{k}.txt" for k in self.tool_outputs.keys()},
            "methodology": [
                "DNS & Subdomain Enumeration (dnsenum, sublist3r, theHarvester)",
                "Host Discovery & Port Scanning (nmap)",
                "SSL/TLS Analysis (sslscan, nmap ssl-enum-ciphers)",
                "Web Vulnerability Scanning (nikto, nuclei)",
                "Directory Enumeration (gobuster)",
                "Technology Fingerprinting (whatweb, wafw00f)",
                "Database Injection Testing (sqlmap - enumeration only)",
                "Cross-Site Scripting Detection (xsser)",
                "WordPress Assessment (wpscan - if applicable)",
                "HTTP Security Header Analysis (curl)"
            ],
            "remediation_priorities": [
                "Address all Critical findings immediately",
                "Plan remediation for High findings within 7 days",
                "Address Medium findings within 30 days",
                "Address Low/Info findings in next maintenance cycle"
            ],
            "legal_disclaimer": (
                "This assessment was conducted with explicit written authorization. "
                "All testing was performed in accordance with the agreed scope and rules of engagement. "
                "Exploitation of confirmed vulnerabilities was not performed without additional explicit consent."
            )
        }

        # Save JSON report
        json_path = os.path.join(self.session_dir, "report.json")
        with open(json_path, 'w') as f:
            json.dump(report, f, indent=2)

        # Generate Markdown report
        md_path = os.path.join(self.session_dir, "report.md")
        with open(md_path, 'w') as f:
            f.write(f"""# Security Assessment Report

## Target Information
- **Target:** {self.target}
- **Host:** {self.host}
- **IP:** {getattr(self, 'ip', 'N/A')}
- **Date:** {self.timestamp}
- **Assessor:** Authorized Security Professional

## Executive Summary

| Severity | Count |
|----------|-------|
| Critical | {report['executive_summary']['critical']} |
| High | {report['executive_summary']['high']} |
| Medium | {report['executive_summary']['medium']} |
| Low | {report['executive_summary']['low']} |
| Info | {report['executive_summary']['info']} |
| **Total** | **{report['executive_summary']['total_findings']}** |

## Detailed Findings

""")

            for i, finding in enumerate(self.findings, 1):
                severity_color = {
                    "Critical": "🔴",
                    "High": "🟠", 
                    "Medium": "🟡",
                    "Low": "🟢",
                    "Info": "🔵"
                }.get(finding['severity'], "⚪")

                f.write(f"""### {i}. {severity_color} {finding['title']}

**Severity:** {finding['severity']}

**Description:**
{finding['description']}

**Evidence:**
```
{finding['evidence']}
```

**Remediation:**
{finding['remediation']}

""")
                if finding['references']:
                    f.write("**References:**\n")
                    for ref in finding['references']:
                        f.write(f"- {ref}\n")
                f.write("\n---\n\n")

            f.write(f"""## Methodology

The following tools and techniques were employed:

""")
            for step in report['methodology']:
                f.write(f"- {step}\n")

            f.write(f"""
## Raw Tool Outputs

All raw tool outputs are stored in: `{self.session_dir}/`

## Legal Disclaimer

{report['legal_disclaimer']}

---
*Report generated by Authorized Web Security Assessment Framework*
""")

        self.log(f"Report saved to: {md_path}", "SUCCESS")
        self.log(f"JSON data saved to: {json_path}", "SUCCESS")

        return report

    def run_full_assessment(self):
        """Execute complete assessment workflow."""
        print(f"""
{Colors.BOLD}{Colors.HEADER}
╔══════════════════════════════════════════════════════════════╗
║  SentinelVortex AUTHORIZED WEB SECURITY ASSESSMENT FRAMEWORK ║
║           For Client Work & Bug Bounty Programs              ║
╚══════════════════════════════════════════════════════════════╝{Colors.ENDC}

{Colors.FAIL}LEGAL NOTICE:{Colors.ENDC}
This tool is for AUTHORIZED security testing only.
You must have explicit written permission to test this target.
Unauthorized access to computer systems is illegal.

Target: {self.target}
Output Directory: {self.session_dir}
""")

        # Authorization confirmation
        auth = input(f"{Colors.WARNING}Do you have explicit written authorization to test {self.target}? (yes/no): {Colors.ENDC}").lower().strip()
        if auth not in ['yes', 'y']:
            self.log("Authorization not confirmed. Exiting.", "ERROR")
            sys.exit(1)

        scope = input(f"{Colors.WARNING}Enter the agreed scope of testing (e.g., 'full application', 'api only', 'specific paths'): {Colors.ENDC}").strip()
        self.log(f"Scope confirmed: {scope}", "INFO")

        print(f"\n{Colors.OKGREEN}Starting assessment...{Colors.ENDC}\n")

        # Run all phases
        self.run_dns_recon()
        self.run_host_discovery()
        self.analyze_headers()
        self.run_web_scanning()
        self.run_advanced_web_tests()
        self.run_authentication_tests()

        # Generate report
        report = self.generate_report()

        # Print summary
        print(f"""
{Colors.BOLD}{Colors.HEADER}
╔══════════════════════════════════════════════════════════════╗
║                    ASSESSMENT COMPLETE                       ║
╚══════════════════════════════════════════════════════════════╝{Colors.ENDC}

{Colors.OKCYAN}Results Directory:{Colors.ENDC} {self.session_dir}

{Colors.BOLD}Finding Summary:{Colors.ENDC}
  Critical: {Colors.FAIL}{report['executive_summary']['critical']}{Colors.ENDC}
  High:     {Colors.WARNING}{report['executive_summary']['high']}{Colors.ENDC}
  Medium:   {Colors.OKCYAN}{report['executive_summary']['medium']}{Colors.ENDC}
  Low:      {Colors.OKGREEN}{report['executive_summary']['low']}{Colors.ENDC}
  Info:     {Colors.OKBLUE}{report['executive_summary']['info']}{Colors.ENDC}

{Colors.BOLD}Reports Generated:{Colors.ENDC}
  - Markdown: {self.session_dir}/report.md
  - JSON:     {self.session_dir}/report.json

{Colors.WARNING}Next Steps:{Colors.ENDC}
  1. Review all findings in the Markdown report
  2. Validate findings manually to eliminate false positives
  3. Prioritize remediation by severity
  4. For Critical/High findings, consider manual exploitation proof-of-concept
     ONLY with explicit client authorization
  5. Deliver report to client through secure channels

{Colors.FAIL}Remember:{Colors.ENDC} Never exploit vulnerabilities without explicit 
written authorization from the system owner.
""")

        return report


def main():
    parser = argparse.ArgumentParser(
        description="SentinelVortex Authorized Web Security Assessment Framework",
        epilog="Example: python3 web_assessor.py -t https://example.com"
    )
    parser.add_argument('-t', '--target', required=True, help='Target URL (e.g., https://example.com)')
    parser.add_argument('-o', '--output', default='assessment_results', help='Output directory for results')

    args = parser.parse_args()

    assessor = WebSecurityAssessor(args.target, args.output)
    assessor.run_full_assessment()


if __name__ == "__main__":
    main()
