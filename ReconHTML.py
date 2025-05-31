import re
import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

init(autoreset=True)

def fetch_html(url):
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(Fore.RED + f"[!] Error fetching URL: {e}")
        return None

def scan_html(html):
    # Expanded regex patterns to catch many common password/key leaks
    patterns = {
        "Password": re.compile(r'(pass(word)?|pwd|secret|api[_-]?key|token|auth[_-]?key|credential|access[_-]?key|private[_-]?key|login|user(pass)?)[\'"\s:=]*([^\s\'"<>]+)', re.I),
        "Email": re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'),
        "AWS Access Key": re.compile(r'AKIA[0-9A-Z]{16}'),
        "AWS Secret Key": re.compile(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])'),
        "Private Key": re.compile(r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----'),
        "JWT Token": re.compile(r'eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'),
        "URL with credentials": re.compile(r'https?://[^/]+:[^@]+@[^/]+'),
        "Credit Card": re.compile(r'\b(?:\d[ -]*?){13,16}\b'),
        "IP Address": re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
    }

    findings = []

    for key, pattern in patterns.items():
        try:
            matches = pattern.findall(html)
            if matches:
                # Flatten matches for patterns that return tuples
                flat_matches = []
                for m in matches:
                    if isinstance(m, tuple):
                        flat_matches.append(m[-1])
                    else:
                        flat_matches.append(m)
                # Remove duplicates
                unique_matches = list(set(flat_matches))
                findings.append((key, unique_matches))
        except re.error as e:
            print(Fore.YELLOW + f"[!] Regex error for {key}: {e}")
            continue

    return findings

def main():
    print("Welcome to ReconHTML, let's explore that website...")

    url = input("Enter the website URL (including http:// or https://): ").strip()
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url

    html = fetch_html(url)
    if html is None:
        print(Fore.RED + "[!] Could not fetch the website HTML. Exiting.")
        return

    print(Fore.GREEN + f"\n[+] Scanning {url} for sensitive information...\n")

    results = scan_html(html)

    if not results:
        print(Fore.GREEN + "[+] No sensitive information found in the HTML.")
    else:
        for category, items in results:
            print(Fore.RED + f"[!] Found possible {category}:")
            for item in items:
                print(Fore.YELLOW + f"  - {item}")
            print()

if __name__ == "__main__":
    main()
