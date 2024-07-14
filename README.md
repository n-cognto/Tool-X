# Security Assessment Toolkit

This toolkit includes three main components for security assessment and vulnerability scanning:

1. Port Vulnerability Scanner
2. Reconnaissance Module
3. Web Application Vulnerability Scanner

These tools are designed for educational purposes and security testing in controlled environments.

## Installation

To use these tools, ensure you have the following dependencies installed:
- `Python 3.x`
- `nmap` and `searchsploit`

Install the required Python packages:

```bash
pip install python-nmap python-whois dnspython requests beautifulsoup4 colorama
```

Ensure searchsploit is installed and up-to-date:

```bash
sudo apt-get install exploitdb
searchsploit -u
```

## Usage

### 1. Port Vulnerability Scanner

To run the port vulnerability scanner:

```bash
python scanner.py <host> <start_port> <end_port>
```

- `<host>`: The IP address or hostname to scan.
- `<start_port>`: The starting port number for the scan.
- `<end_port>`: The ending port number for the scan.

Example:

```bash
python tool_x.py 192.168.0.12 1 9000
```

### 2. Reconnaissance Module

To run the reconnaissance module:

```bash
python recon_module.py
```

You will be prompted to enter the target domain. The tool will perform various reconnaissance tasks and save the results in a new directory named after the target domain.

### 3. Web Application Vulnerability Scanner

To run the web application vulnerability scanner:

```bash
python vulnerability_scanner.py
```

You will be prompted to enter the target URL. The tool will scan for common web application vulnerabilities.

## Examples

### Port Vulnerability Scanner Output:

```
Open Ports on 127.0.0.1:
902/tcp open vmware-auth 1.10
3306/tcp open mysql 5.5.5-10.11.6-MariaDB-2
8080/tcp open http 0.6

Potential Vulnerabilities:
Port 8080 - http 0.6:
Flexense HTTP Server 10.6.24 - Buffer Overflow  | multiple/remote/51493.rb
GWeb HTTP Server 0.5/0.6 - Directory Traversal  | windows/remote/23758.txt
```

### Reconnaissance Module Output:

The tool will create a directory with the target domain name and save various files containing information about WHOIS, DNS records, subdomains, technology stack, robots.txt, and sitemap.xml.

### Web Application Vulnerability Scanner Output:

```
Starting vulnerability scan for https://example.com
No SQL Injection vulnerabilities detected.
No XSS vulnerabilities detected.
No Open Redirect vulnerabilities detected.
No Directory Listing vulnerabilities detected.
SSL/TLS version is up to date: TLSv1.2
SSL certificate is valid until 2025-01-01 00:00:00

No vulnerabilities detected.
```

## Disclaimer

These tools are for educational purposes only. Always obtain proper authorization before scanning or testing any systems or networks you do not own or have explicit permission to test.
