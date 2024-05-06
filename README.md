# Port Vulnerability Scanner

This tool scans a specified range of ports, identifies open ports, and uses `searchsploit` to find known vulnerabilities based on service and version information. This project is designed for educational purposes and security testing in controlled environments.

## Installation

To use this tool, ensure you have the following dependencies installed:
- `Python`
- `nmap` and `searchsploit`
- Python libraries used: `argparse`, `nmap`, and `subprocess`

To install the required Python packages, use:
```bash
pip install python-nmap
  ```
Ensure searchsploit is installed and up-to-date:

```bash
sudo apt-get install exploitdb
```
```bash
searchsploit -u
```
Usage
To run the vulnerability scanner, specify the target host and port range as command-line arguments:

```bash
python scanner.py <host> <start_port> <end_port>
```

<host>: The IP address or hostname to scan.
<start_port>: The starting port number for the scan.
<end_port>: The ending port number for the scan.

Example:
```bash
python scanner.py 127.0.0.1 1 9000
```
This command scans localhost (127.0.0.1) from port 1 to 9000 for open ports and checks for known vulnerabilities.

Examples
After running the script, you'll see a list of open ports with service and version information, followed by a list of potential vulnerabilities:

```bash
Open Ports on 127.0.0.1:
902/tcp open vmware-auth 1.10
3306/tcp open mysql 5.5.5-10.11.6-MariaDB-2
8080/tcp open http 0.6

Potential Vulnerabilities:
Port 8080 - http 0.6:
Flexense HTTP Server 10.6.24 - Buffer Overflow  | multiple/remote/51493.rb
GWeb HTTP Server 0.5/0.6 - Directory Traversal  | windows/remote/23758.txt
```
