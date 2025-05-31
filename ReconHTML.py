#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
import re
import time
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Default realistic browser headers
DEFAULT_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/114.0.0.0 Safari/537.36"),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept": ("text/html,application/xhtml+xml,application/xml;"
               "q=0.9,image/webp,*/*;q=0.8"),
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}

# Google-like headers with Referer and Googlebot User-Agent
GOOGLE_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/114.0.0.0 Safari/537.36"),
    "Referer": "https://www.google.com/",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept": ("text/html,application/xhtml+xml,application/xml;"
               "q=0.9,image/webp,*/*;q=0.8"),
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

def fetch_html_with_retry(url, headers, max_retries=5):
    retry_delay = 5  # seconds initial backoff delay
    for attempt in range(1, max_retries + 1):
        try:
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                return response.text
            elif response.status_code == 429:
                wait = response.headers.get("Retry-After")
                if wait and wait.isdigit():
                    wait_time = int(wait)
                    print(f"{Fore.YELLOW}[!] Rate limited. Retrying after {wait_time} seconds... (Attempt {attempt}/{max_retries})")
                    time.sleep(wait_time)
                else:
                    print(f"{Fore.YELLOW}[!] Rate limited. Retrying after {retry_delay} seconds... (Attempt {attempt}/{max_retries})")
                    time.sleep(retry_delay)
                    retry_delay *= 2
            else:
                print(f"{Fore.RED}[!] Unexpected status code {response.status_code}. Retrying... (Attempt {attempt}/{max_retries})")
                time.sleep(retry_delay)
                retry_delay *= 2
        except requests.RequestException as e:
            print(f"{Fore.RED}[!] Request error: {e}. Retrying in {retry_delay} seconds... (Attempt {attempt}/{max_retries})")
            time.sleep(retry_delay)
            retry_delay *= 2
    print(f"{Fore.RED}[!] Max retries reached. Failed to fetch URL: {url}")
    return None

# Expanded regex patterns for sensitive data detection
PATTERNS = {
    "Passwords": re.compile(
        r"(password|passwd|pass|pwd|secret|token|api[-_]?key|apikey|auth|credential|sessionid|sessid)"
        r"\s*[:=]\s*['\"]?[^'\"\s<>]{3,}['\"]?", re.IGNORECASE),
    "Email Addresses": re.compile(
        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    "Private Keys": re.compile(
        r"-----BEGIN (RSA|DSA|EC|PGP|OPENSSH|PRIVATE) KEY-----.*?-----END \1 KEY-----",
        re.DOTALL),
    "AWS Keys": re.compile(
        r"AKIA[0-9A-Z]{16}"),
    "Google API Keys": re.compile(
        r"AIza[0-9A-Za-z-_]{35}"),
    "IP Addresses": re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "Credit Card Numbers": re.compile(
        r"\b(?:\d[ -]*?){13,16}\b"),
    "JWT Tokens": re.compile(
        r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "URL with Basic Auth": re.compile(
        r"https?:\/\/[^\s:@]+:[^\s:@]+@[^\s]+"),
}

def scan_html_for_sensitive_data(html):
    findings = {}
    for name, pattern in PATTERNS.items():
        matches = pattern.findall(html)
        if matches:
            findings[name] = matches
    return findings

def scan_website(url):
    print(f"\n{Fore.CYAN}Fetching {url} using default headers...")
    html = fetch_html_with_retry(url, DEFAULT_HEADERS)
    if html is None:
        print(f"{Fore.YELLOW}Retrying with Google-like headers...")
        html = fetch_html_with_retry(url, GOOGLE_HEADERS)
        if html is None:
            print(f"{Fore.RED}Failed to retrieve website HTML with all methods.")
            return

    print(f"\n{Fore.CYAN}Scanning for sensitive information leaks...\n")
    findings = scan_html_for_sensitive_data(html)

    if not findings:
        print(f"{Fore.GREEN}No sensitive information detected in the HTML.")
    else:
        for category, matches in findings.items():
            print(f"{Fore.RED}[!] Detected {category}:")
            unique_matches = set(matches)
            for m in unique_matches:
                display_match = m if len(m) < 80 else m[:77] + "..."
                print(f"   {Fore.YELLOW}{display_match}")
            print()

def main():
    print("Welcome to ReconHTML, let's explore that website...")
    while True:
        url = input("\nEnter the website URL (include http:// or https://): ").strip()
        if not url:
            print(f"{Fore.RED}Please enter a valid URL.")
            continue

        scan_website(url)

        again = input(f"{Fore.CYAN}Would you like to scan another website? (y/n): ").strip().lower()
        if again != 'y':
            print(f"{Fore.GREEN}Exiting ReconHTML. Stay safe!")
            break

if __name__ == "__main__":
    main()
