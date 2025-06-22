# Tool-X Security Assessment Toolkit

This comprehensive security toolkit includes five main components for security assessment, vulnerability scanning, and penetration testing:

1. **Port Vulnerability Scanner** (`tool_x.py`) - Network port scanning with vulnerability detection
2. **Reconnaissance Module** (`recon_module.py`) - Domain intelligence gathering and enumeration
3. **Web Application Vulnerability Scanner** (`vulnerability_scanner.py`) - Web app security assessment
4. **WordPress Brute Force Tool** (`wp_bruteforce.py`) - WordPress login brute force testing
5. **Linux WiFi Extractor** (`linux_wifi_extractor.py`) - WiFi network information extraction

These tools are designed for educational purposes and authorized security testing in controlled environments.

## Installation

To use these tools, ensure you have the following dependencies installed:

### System Requirements
- `Python 3.x`
- `nmap` (for port scanning)
- `searchsploit` (for vulnerability database)
- `nmcli` (for WiFi extraction - usually pre-installed on Linux)

### Python Dependencies

Install the required Python packages:

```bash
pip install python-nmap python-whois dnspython requests beautifulsoup4 colorama
```

### Additional Tools

Ensure searchsploit is installed and up-to-date:

```bash
sudo apt-get install exploitdb
searchsploit -u
```

For the WiFi extractor, ensure NetworkManager is installed (usually pre-installed on most Linux distributions):

```bash
sudo apt-get install network-manager
```

## Usage

### 1. Port Vulnerability Scanner (`tool_x.py`)

Scans network ports and identifies potential vulnerabilities using the ExploitDB database.

```bash
python tool_x.py <host> <start_port> <end_port>
```

**Parameters:**
- `<host>`: The IP address or hostname to scan
- `<start_port>`: The starting port number for the scan
- `<end_port>`: The ending port number for the scan

**Example:**
```bash
python tool_x.py 192.168.0.12 1 9000
```

### 2. Reconnaissance Module (`recon_module.py`)

Performs comprehensive domain intelligence gathering including WHOIS, DNS enumeration, subdomain discovery, and technology stack identification.

```bash
python recon_module.py
```

You will be prompted to enter the target domain. The tool will:
- Gather WHOIS information
- Enumerate DNS records
- Discover subdomains
- Identify technology stack
- Analyze robots.txt and sitemap.xml
- Perform port scanning on discovered IP

Results are saved in a directory named after the target domain.

### 3. Web Application Vulnerability Scanner (`vulnerability_scanner.py`)

Scans web applications for common vulnerabilities including SQL injection, XSS, open redirects, and SSL/TLS issues.

```bash
python vulnerability_scanner.py
```

You will be prompted to enter the target URL. The scanner will test for:
- SQL Injection vulnerabilities
- Cross-Site Scripting (XSS)
- Open Redirect vulnerabilities
- Directory listing issues
- SSL/TLS configuration problems

### 4. WordPress Brute Force Tool (`wp_bruteforce.py`)

Multi-threaded WordPress login brute force tool for authorized penetration testing.

```bash
python wp_bruteforce.py <target_url> [options]
```

**Options:**
- `-u, --userlist`: Username wordlist file
- `-p, --passwordlist`: Password wordlist file
- `-t, --threads`: Number of threads (default: 10)
- `-d, --delay`: Delay between requests in seconds (default: 0.1)
- `--create-wordlists`: Create sample wordlist files

**Examples:**
```bash
# Basic usage with default wordlists
python wp_bruteforce.py http://target-wordpress-site.com

# Using custom wordlists
python wp_bruteforce.py http://target-site.com -u users.txt -p passwords.txt -t 20

# Create sample wordlists
python wp_bruteforce.py --create-wordlists
```

### 5. Linux WiFi Extractor (`linux_wifi_extractor.py`)

Extracts WiFi network information and passwords from a Linux system using NetworkManager.

```bash
python linux_wifi_extractor.py
```

This tool will:
- List all available WiFi networks
- Show security information for each network
- Attempt to extract stored passwords for known networks
- Display SSID, security type, and passwords (if available)

## Examples

### Port Vulnerability Scanner Output:

```
**************************************
  Port        Vulnerability       Scanner
  Visit the project on GitHub: https://github.com/phantom-kali
**************************************

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

The tool creates a directory with the target domain name and saves various files containing:
- WHOIS information (registrar, creation date, expiration date)
- DNS records (A, AAAA, CNAME, MX, NS, TXT, SOA)
- Discovered subdomains
- Technology stack identification
- robots.txt and sitemap.xml analysis
- Open ports scan results

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

### WordPress Brute Force Tool Output:

```
[*] Target: http://target-site.com/wp-login.php
[*] Users: 7
[*] Passwords: 20
[*] Threads: 10
[*] Total combinations: 140
--------------------------------------------------
[*] Starting brute force attack...
[*] Testing 140 combinations...
[+] Credential found: admin:password123
==================================================
[*] Attack completed in 15.32 seconds
[*] Total attempts: 140
[*] Rate: 9.14 attempts/second
[+] Found 1 valid credentials:
    admin:password123
```

### Linux WiFi Extractor Output:

```
Available Wi-Fi Networks:
SSID: MyHomeNetwork
Security: WPA2
Password for MyHomeNetwork: mypassword123

SSID: OfficeWiFi
Security: WPA3
Could not retrieve password for OfficeWiFi.

SSID: PublicHotspot
Security: 
Password for PublicHotspot: 
```

## Features

### Port Vulnerability Scanner
- Fast network port scanning using nmap
- Service version detection
- Automatic vulnerability lookup using ExploitDB
- Detailed vulnerability information with exploit references

### Reconnaissance Module
- WHOIS information gathering
- Complete DNS record enumeration
- Subdomain discovery
- Technology stack identification
- Web crawling for robots.txt and sitemap.xml
- Multi-threaded operations for faster results

### Web Application Scanner
- SQL Injection detection
- Cross-Site Scripting (XSS) testing
- Open Redirect vulnerability detection
- Directory listing vulnerability checks
- SSL/TLS configuration analysis
- Certificate validity verification

### WordPress Brute Force Tool
- Multi-threaded brute force attacks
- Custom wordlist support
- Rate limiting and delay controls
- User enumeration capabilities
- Comprehensive credential testing
- Built-in common password generation

### Linux WiFi Extractor
- WiFi network enumeration
- Security type identification
- Password extraction for stored networks
- NetworkManager integration

## Security Notes

- **Rate Limiting**: The WordPress brute force tool includes delay controls to avoid triggering security measures
- **Detection Avoidance**: Tools use realistic user agents and request patterns
- **Error Handling**: Comprehensive error handling for network issues and edge cases
- **Multi-threading**: Optimized for performance while maintaining stability

## Disclaimer

⚠️ **IMPORTANT**: These tools are for educational purposes and authorized security testing only. 

- Always obtain proper written authorization before scanning or testing any systems or networks you do not own
- Unauthorized access to computer systems is illegal in most jurisdictions
- Use these tools responsibly and ethically
- The authors are not responsible for any misuse of these tools
- These tools should only be used in controlled environments or on systems you own

## Legal Notice

This toolkit is intended for:
- Educational purposes and learning cybersecurity concepts
- Authorized penetration testing engagements
- Security research in controlled environments
- Testing your own systems and networks

**DO NOT** use these tools for:
- Unauthorized testing of systems you don't own
- Malicious activities or attacks
- Any illegal purposes
