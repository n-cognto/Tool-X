import argparse
import nmap
import subprocess


def print_banner():
    print("\n**************************************")
    print("  Port        Vulnerability       Scanner")
    print("  Visit the project on GitHub: https://github.com/phantom-kali")
    print("**************************************\n")


def scan_ports(host, start_port, end_port):
    nm = nmap.PortScanner()
    nm.scan(hosts=host, arguments=f"-sV -p {start_port}-{end_port}")

    open_ports = []

    if host in nm.all_hosts():
        try:
            for port in nm[host]["tcp"]:
                if nm[host]["tcp"][port]["state"] == "open":
                    port_info = {
                        "port": port,
                        "service": nm[host]["tcp"][port]["name"],
                        "version": nm[host]["tcp"][port].get("version", "unknown"),
                    }
                    open_ports.append(port_info)
        except Exception as e:
            print("Error while scanning ports:", e)
    
    return open_ports


def find_vulnerabilities(service_info):
    vulnerabilities = []

    for service in service_info:
        query = f"{service['service']} {service['version']}"

        try:
            # Run searchsploit to find known exploits based on the service and version
            result = subprocess.run(
                ["searchsploit", "-s", query],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                lines = result.stdout.split("\n")
                separator = [line for line in lines if "---" in line]
                if separator:
                    separator_idx = lines.index(separator[0])
                    exploits = [exp.strip() for exp in lines[separator_idx + 1:] if exp.strip()]

                    for exploit in exploits:
                        vulnerabilities.append({
                            "port": service["port"],
                            "service": service["service"],
                            "version": service["version"],
                            "exploit": exploit,
                        })
        except Exception as e:
            print(f"Error while finding vulnerabilities with searchsploit: {e}")

    return vulnerabilities


if __name__ == "__main__":
    print_banner()  # Display the banner and GitHub link
    
    parser = argparse.ArgumentParser(description="Scan ports and find vulnerabilities with searchsploit.")
    parser.add_argument("host", help="The target host to scan.")
    parser.add_argument("start_port", type=int, help="The starting port number.")
    parser.add_argument("end_port", type=int, help="The ending port number.")

    args = parser.parse_args()

    # Scan for open ports with service/version information
    open_ports = scan_ports(args.host, args.start_port, args.end_port)
    
    if not open_ports:
        print("No open ports found.")
    else:
        print(f"Open Ports on {args.host}:")
        for port_info in open_ports:
            print(f"{port_info['port']}/tcp open {port_info['service']} {port_info['version']}")

    vulnerabilities = find_vulnerabilities(open_ports)
    
    if vulnerabilities:
        print("\nPotential Vulnerabilities:")
        for vulnerability in vulnerabilities:
            print(
                f"Port {vulnerability['port']} - {vulnerability['service']} {vulnerability['version']}:\n"
                f"{vulnerability['exploit']}\n"
            )
    else:
        print("No vulnerabilities found.")
