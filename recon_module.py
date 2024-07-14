import whois
import dns.resolver
import requests
from bs4 import BeautifulSoup
import socket
import subprocess
import concurrent.futures
import json
import os
from colorama import init, Fore, Back, Style

# Initialize colorama
init(autoreset=True)

def gather_whois(domain):
    try:
        w = whois.whois(domain)
        return {
            'registrar': w.registrar,
            'creation_date': w.creation_date,
            'expiration_date': w.expiration_date,
            'name_servers': w.name_servers
        }
    except Exception as e:
        return f"WHOIS Error: {str(e)}"

def get_dns_records(domain):
    records = {}
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [str(rdata) for rdata in answers]
        except Exception:
            records[record_type] = []
    return records

def enumerate_subdomains(domain):
    subdomains = set()
    wordlist = ["www", "mail", "ftp", "webmail", "login", "admin", "test", "dev", "blog", "shop", "api"]
    
    def check_subdomain(subdomain):
        try:
            socket.gethostbyname(f"{subdomain}.{domain}")
            subdomains.add(f"{subdomain}.{domain}")
        except socket.error:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(check_subdomain, wordlist)
    
    return list(subdomains)

def identify_tech_stack(url):
    try:
        response = requests.get(f"http://{url}", timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        tech_stack = {
            'server': response.headers.get('Server', 'Unknown'),
            'programming_language': 'Unknown',
            'frameworks': [],
            'cms': 'Unknown'
        }

        # Check for common frameworks and technologies
        if 'wp-content' in response.text:
            tech_stack['cms'] = 'WordPress'
        elif 'Drupal' in response.text:
            tech_stack['cms'] = 'Drupal'
        elif 'Joomla' in response.text:
            tech_stack['cms'] = 'Joomla'

        if 'PHP' in response.headers.get('X-Powered-By', ''):
            tech_stack['programming_language'] = 'PHP'
        elif 'ASP.NET' in response.headers.get('X-Powered-By', ''):
            tech_stack['programming_language'] = 'ASP.NET'
        elif 'Django' in response.text:
            tech_stack['programming_language'] = 'Python'
            tech_stack['frameworks'].append('Django')
        elif 'Ruby on Rails' in response.text:
            tech_stack['programming_language'] = 'Ruby'
            tech_stack['frameworks'].append('Ruby on Rails')

        # Check for JavaScript frameworks
        if 'react' in response.text.lower():
            tech_stack['frameworks'].append('React')
        if 'vue' in response.text.lower():
            tech_stack['frameworks'].append('Vue.js')
        if 'angular' in response.text.lower():
            tech_stack['frameworks'].append('Angular')

        return tech_stack
    except Exception as e:
        return f"Tech Stack Error: {str(e)}"

def scan_ports(ip):
    try:
        result = subprocess.run(['nmap', '-F', ip], capture_output=True, text=True)
        lines = result.stdout.split('\n')
        processed_output = []
        for line in lines:
            if 'PORT' in line or 'tcp' in line or 'Nmap done' in line:
                processed_output.append(line.strip())
        return '\n'.join(processed_output)
    except Exception as e:
        return f"Port Scan Error: {str(e)}"

def analyze_robots_sitemap(domain):
    robots_url = f"http://{domain}/robots.txt"
    sitemap_url = f"http://{domain}/sitemap.xml"
    results = {'robots.txt': None, 'sitemap.xml': None}
    
    def save_to_file(content, filename):
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
        return f"Saved to {filename}"

    try:
        robots_response = requests.get(robots_url)
        if robots_response.status_code == 200:
            results['robots.txt'] = save_to_file(robots_response.text, f"{domain}_robots.txt")
    except:
        results['robots.txt'] = "Failed to retrieve robots.txt"

    try:
        sitemap_response = requests.get(sitemap_url)
        if sitemap_response.status_code == 200:
            results['sitemap.xml'] = save_to_file(sitemap_response.text, f"{domain}_sitemap.xml")
    except:
        results['sitemap.xml'] = "Failed to retrieve sitemap.xml"

    return results

def format_output(results):
    output = ""
    
    def add_section(title, content):
        if isinstance(content, str):
            formatted_content = content
        else:
            formatted_content = json.dumps(content, indent=2, default=str)
        return f"{Fore.CYAN}{Style.BRIGHT}{title}:\n{Style.RESET_ALL}{formatted_content}\n\n"
    
    output += add_section("WHOIS Information", results['whois'])
    output += add_section("DNS Records", results['dns_records'])
    output += add_section("Subdomains", results['subdomains'])
    output += add_section("Technology Stack", results['tech_stack'])
    output += add_section("Robots.txt and Sitemap", results['robots_sitemap'])
    output += add_section("Open Ports", results['open_ports'])
    
    return output

def recon_module(domain):
    print(f"{Fore.GREEN}{Style.BRIGHT}Starting reconnaissance on {domain}{Style.RESET_ALL}\n")
    results = {}
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_whois = executor.submit(gather_whois, domain)
        future_dns = executor.submit(get_dns_records, domain)
        future_subdomains = executor.submit(enumerate_subdomains, domain)
        future_tech = executor.submit(identify_tech_stack, domain)
        future_robots_sitemap = executor.submit(analyze_robots_sitemap, domain)

        try:
            ip = socket.gethostbyname(domain)
            future_ports = executor.submit(scan_ports, ip)
        except socket.gaierror:
            future_ports = None

        results['whois'] = future_whois.result()
        results['dns_records'] = future_dns.result()
        results['subdomains'] = future_subdomains.result()
        results['tech_stack'] = future_tech.result()
        results['robots_sitemap'] = future_robots_sitemap.result()
        if future_ports:
            results['open_ports'] = future_ports.result()
        else:
            results['open_ports'] = "Unable to resolve IP for port scanning"

    return results

if __name__ == "__main__":
    target_domain = input(f"{Fore.YELLOW}Enter the target domain: {Style.RESET_ALL}")
    
    output_dir = f"{target_domain}_recon_output"
    os.makedirs(output_dir, exist_ok=True)
    os.chdir(output_dir)
    
    recon_results = recon_module(target_domain)
    print(format_output(recon_results))
    print(f"{Fore.GREEN}Reconnaissance complete. Output files saved in {output_dir}")
