"""
ReconHTML - Powerful Defensive HTML & JS Sensitive Data Scanner
Created by George Ragsdale, 2025
"""

import re
import requests
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
import tkinter as tk
from tkinter import scrolledtext
import threading

# Expanded sensitive patterns for detection
SENSITIVE_PATTERNS = {
    "API Key": r"\b(?i)(api[_-]?key)[\"'=:\s>]{1,}[\"']?[a-zA-Z0-9_\-]{16,}[\"']?",
    "Secret Key": r"\b(?i)(secret)[\"'=:\s>]{1,}[\"']?[a-zA-Z0-9_\-\/+=]{8,}[\"']?",
    "Password Field": r"<input[^>]*type\s*=\s*[\"']password[\"'][^>]*>",
    "Hardcoded Password": r"\b(?i)(password|passwd|pwd|pass)[\"'=:\s>]{1,}[\"']?[a-zA-Z0-9_\-]{4,}[\"']?",
    "Auth Token": r"\b(?i)(auth|bearer)[\"'=:\s>]{1,}[\"']?[a-zA-Z0-9\-_\.=]{10,}[\"']?",
    "JWT": r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"
}

def scan_content(label: str, content: str):
    """
    Scan a block of text for sensitive patterns.
    Returns list of tuples: (pattern name, matches list)
    """
    findings = []
    for tag, pattern in SENSITIVE_PATTERNS.items():
        try:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            if matches:
                # Flatten tuples if regex groups exist
                matches = [match if isinstance(match, str) else match[0] for match in matches]
                findings.append((f"{label} → {tag}", list(set(matches))))
        except Exception as e:
            findings.append((f"{label} → {tag}", [f"Pattern error: {str(e)}"]))
    return findings

def scan_url_with_enhancements(url):
    """
    Load the webpage with Playwright, extract HTML, inline/external JS,
    storage, cookies, iframes, and scan them all for sensitive data.
    """
    all_findings = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        try:
            page.goto(url, timeout=30000)
            page.wait_for_load_state("networkidle", timeout=10000)
            html = page.content()
            soup = BeautifulSoup(html, "html.parser")

            # Scan main HTML
            all_findings.extend(scan_content("Main Page", html))

            # Scan inline scripts
            try:
                scripts = soup.find_all("script", src=False)
                for i, script in enumerate(scripts):
                    if script.string:
                        all_findings.extend(scan_content(f"Inline JS #{i+1}", script.string))
            except Exception as e:
                all_findings.append(("Inline Script Scan", [f"Error: {str(e)}"]))

            # Scan external scripts
            try:
                scripts = soup.find_all("script", src=True)
                for i, script in enumerate(scripts):
                    src = script['src']
                    full_url = src if src.startswith("http") else requests.compat.urljoin(url, src)
                    try:
                        res = requests.get(full_url, timeout=10)
                        res.raise_for_status()
                        all_findings.extend(scan_content(f"External JS #{i+1}", res.text))
                    except Exception as e:
                        all_findings.append((f"External JS #{i+1}", [f"Fetch error: {str(e)}"]))
            except Exception as e:
                all_findings.append(("External JS Scan", [f"Error: {str(e)}"]))

            # Scan localStorage
            try:
                local_storage = page.evaluate("() => JSON.stringify(localStorage)")
                all_findings.extend(scan_content("localStorage", local_storage))
            except Exception as e:
                all_findings.append(("localStorage", [f"Error: {str(e)}"]))

            # Scan sessionStorage
            try:
                session_storage = page.evaluate("() => JSON.stringify(sessionStorage)")
                all_findings.extend(scan_content("sessionStorage", session_storage))
            except Exception as e:
                all_findings.append(("sessionStorage", [f"Error: {str(e)}"]))

            # Scan cookies
            try:
                cookies = page.context.cookies()
                for cookie in cookies:
                    all_findings.extend(scan_content("Cookie", str(cookie)))
            except Exception as e:
                all_findings.append(("Cookies", [f"Error: {str(e)}"]))

            # Scan iframes
            try:
                for frame in page.frames:
                    try:
                        frame_html = frame.content()
                        all_findings.extend(scan_content("Iframe", frame_html))
                    except Exception as e:
                        all_findings.append(("Iframe", [f"Frame content error: {str(e)}"]))
            except Exception as e:
                all_findings.append(("Iframes", [f"Error: {str(e)}"]))

        except Exception as e:
            all_findings.append(("Page Load", [f"Error: {str(e)}"]))

        browser.close()

    return all_findings

def typewriter_text(widget, text, delay=100, callback=None):
    """
    Typewriter effect for Tkinter Label widget.
    """
    def inner_type(i=0):
        if i <= len(text):
            widget.config(text=text[:i])
            widget.after(delay, inner_type, i+1)
        else:
            if callback:
                callback()
    inner_type()

def show_intro_then_prompt():
    """
    Show the intro text with typewriter effect, then show URL input UI.
    """
    intro_label.pack(pady=10)
    url_entry.pack_forget()
    scan_button.pack_forget()
    results_text.pack_forget()

    def after_intro():
        intro_label.config(text="Enter URL to Scan:")
        url_entry.pack(side=tk.LEFT, padx=5)
        scan_button.pack(side=tk.LEFT)
        results_text.pack(padx=10, pady=10)

    typewriter_text(intro_label, "Welcome To ReconHTML, lets explore that website...", delay=80, callback=after_intro)

def run_scan():
    """
    Run the scan in a thread to keep GUI responsive.
    """
    url = url_entry.get()
    scan_button.config(state="disabled")
    results_text.delete(1.0, tk.END)
    results_text.insert(tk.END, f"Scanning {url}...\n\n")

    def threaded_scan():
        findings = scan_url_with_enhancements(url)
        for label, matches in findings:
            results_text.insert(tk.END, f"[{label}]\n")
            for match in matches:
                results_text.insert(tk.END, f"  - {match}\n")
            results_text.insert(tk.END, "\n")
        scan_button.config(state="normal")

    threading.Thread(target=threaded_scan).start()


# --- GUI Setup ---

root = tk.Tk()
root.title("ReconHTML - Created by George Ragsdale, 2025")
root.geometry("900x700")

frame = tk.Frame(root)
frame.pack(pady=10)

intro_label = tk.Label(frame, text="", font=("Consolas", 14))
url_entry = tk.Entry(frame, width=60)
scan_button = tk.Button(frame, text="Scan", command=run_scan)
results_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=110, height=35)

show_intro_then_prompt()

root.mainloop()
