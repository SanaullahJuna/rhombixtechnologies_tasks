# Rhombix Technologies - Bug Bounty Toolkit

## Features
- Multi-threaded port scanning (20 ports in parallel)
- Subdomain enumeration with custom wordlists
- Directory bruteforcing
- Security headers analysis (CSP, HSTS, X-Frame, etc.)
- SSL certificate checking
- Real-time file-based logging
- Configurable settings (ports, wordlists, timeouts)
- Professional report generation

## Requirements
- Python 3.8+
- `pip install requests`

## Usage
1. Run: `python bug_bounty_toolkit.py`
2. Enter target URL (e.g., http://neverssl.com)
3. Click "Start Scan"
4. File → Generate Report

## Sample Scan Results
- Found 15 subdomains
- Identified 5 missing security headers
- DNS resolution successful

## Author
Sanaullah Juna - Rhombix Technologies Intern
