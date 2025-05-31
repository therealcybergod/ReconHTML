#!/usr/bin/env python3
"""
ReconHTML - An HTML scanner that checks websites for leaked sensitive data.
Created by George Ragsdale, 2025.
"""

import requests
from bs4 import BeautifulSoup
import re

def fetch_html(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        print("[+] Successfully fetched HTML content.")
        return response.text
    except Exception as e:
        print(f"[!] Error fetching URL: {e}")
        return ""

def run_checks(html):
    soup = BeautifulSoup(html, 'html.parser')
    findings = []

    # Helper to run a check safely
    def safe_check(func, label):
        try:
            results = func(soup)
            if results:
                findings.extend(results)
        except Exception as e:
            print(f"[!] Error in {label}: {e}")

    # List of checks to perform
    checks = [
        (check_sensitive_inputs, "Sensitive Inputs"),
        (check_comments_for_leaks, "Comment Leaks"),
        (check_inline_js_for_leaks, "Inline JS"),
        (check_meta_tags_for_info, "Meta Tags"),
        (check_text_for_keywords, "Visible Keywords"),
    ]

    for func, label in checks:
        safe_check(func, label)

    return findings

# 1. Input fields with suspicious names
def check_sensitive_inputs(soup):
    keywords = r"(pass(word)?|pwd|token|secret|key|api[_-]?key|auth|session|credential)"
    results = []
    for input_tag in soup.find_all("input"):
        name = input_tag.get("name", "")
        id_ = input_tag.get("id", "")
        if re.search(keywords, name, re.I) or re.search(keywords, id_, re.I):
            results.append(f"Sensitive-looking input field: name='{name}' id='{id_}'")
    return results

# 2. Comments with sensitive data
def check_comments_for_leaks(soup):
    keywords = r"(password|secret|key|token|TODO|FIXME|debug|admin|auth)"
    results = []
    for comment in soup.find_all(string=lambda text: isinstance(text, str) and "<!--" in text):
        if re.search(keywords, comment, re.I):
            results.append(f"Suspicious comment: {comment.strip()[:100]}")
    return results

# 3. Inline JavaScript leaks
def check_inline_js_for_leaks(soup):
    keywords = r"(var|let|const)?\s*(password|pass|secret|token|apikey|session|auth)[\s:=]+[\"']?.+?[\"']?"
    results = []
    for script in soup.find_all("script"):
        if script.string:
            lines = script.string.split("\n")
            for line in lines:
                if re.search(keywords, line, re.I):
                    results.append(f"Suspicious inline JS: {line.strip()}")
    return results

# 4. Metadata that might leak internal info
def check_meta_tags_for_info(soup):
    keywords = r"(generator|powered|framework|server|cms)"
    results = []
    for meta in soup.find_all("meta"):
        name = meta.get("name", "")
        content = meta.get("content", "")
        if re.search(keywords, name, re.I) or re.search(keywords, content, re.I):
            results.append(f"Meta tag leak: name='{name}', content='{content}'")
    return results

# 5. Text nodes that look like secrets
def check_text_for_keywords(soup):
    keywords = r"(password\s*[:=]\s*.+|api[_-]?key\s*[:=]\s*.+|token\s*[:=]\s*.+)"
    results = []
    for text in soup.stripped_strings:
        if re.search(keywords, text, re.I):
            results.append(f"Visible potential leak: {text}")
    return results

# === Main Execution ===

def main():
    print("\n🚨 Welcome to ReconHTML - Let's explore that website...")
    url = input("🌐 Enter a website URL to scan: ").strip()

    if not url.startswith("http"):
        url = "http://" + url

    html = fetch_html(url)
    if not html:
        print("[!] No HTML content retrieved. Exiting.")
        return

    print("\n🔍 Scanning for sensitive content...\n")
    findings = run_checks(html)

    if findings:
        print("\n🛑 Potential Issues Found:")
        for f in findings:
            print(f" - {f}")
    else:
        print("✅ No obvious sensitive information found.")

if __name__ == "__main__":
    main()
