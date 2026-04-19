# Author: Anees
# Vulnerability: Missing HTTP Security Headers
# Target: api.0x10.cloud
# Course: COMP2152 — Term Project

import urllib.request
import time

TARGET = "http://api.0x10.cloud"
TIMEOUT = 5

# Security headers that every production server should return
REQUIRED_HEADERS = {
    "Strict-Transport-Security": (
        "Prevents browsers from connecting over plain HTTP. "
        "Without it, attackers can downgrade HTTPS to HTTP (MITM)."
    ),
    "X-Frame-Options": (
        "Blocks the page from being embedded in an iframe. "
        "Without it, attackers can trick users via clickjacking."
    ),
    "Content-Security-Policy": (
        "Restricts which scripts/resources can run on the page. "
        "Without it, XSS attacks are easier to execute."
    ),
    "X-Content-Type-Options": (
        "Stops browsers from guessing the content type. "
        "Without it, MIME-sniffing attacks are possible."
    ),
    "Referrer-Policy": (
        "Controls how much referrer info is sent in requests. "
        "Without it, sensitive URL data can leak to third parties."
    ),
    "Permissions-Policy": (
        "Limits access to browser APIs (camera, mic, etc). "
        "Without it, malicious scripts can access device features."
    ),
}

print("=" * 60)
print("  Missing HTTP Security Headers — Vulnerability Scanner")
print(f"  Target : {TARGET}")
print("=" * 60)

try:
    print(f"\n[*] Sending HTTP GET request to {TARGET}...")
    time.sleep(0.15)

    req = urllib.request.Request(TARGET, headers={"User-Agent": "SecurityScanner/1.0"})
    response = urllib.request.urlopen(req, timeout=TIMEOUT)
    headers = dict(response.headers)

    # Normalize header keys to lowercase for case-insensitive comparison
    headers_lower = {k.lower(): v for k, v in headers.items()}

    print(f"[+] HTTP Status  : {response.status}")
    print(f"[+] Server       : {headers.get('Server', 'Not disclosed')}")
    print(f"[+] X-Powered-By : {headers.get('X-Powered-By', 'Not disclosed')}")
    print()

    missing = []
    present = []

    for header, explanation in REQUIRED_HEADERS.items():
        if header.lower() in headers_lower:
            present.append(header)
            print(f"[+] PRESENT  : {header}")
        else:
            missing.append((header, explanation))
            print(f"[-] MISSING  : {header}")

    print()

    if missing:
        print("=" * 60)
        print("  VULNERABILITY CONFIRMED")
        print("=" * 60)
        print(f"  {len(missing)} of {len(REQUIRED_HEADERS)} required security headers are MISSING\n")
        for header, explanation in missing:
            print(f"  ✗ {header}")
            print(f"    → {explanation}")
            print()
        print("  RISK: Missing security headers leave the application")
        print("  exposed to clickjacking, cross-site scripting (XSS),")
        print("  MITM downgrade attacks, and MIME-type confusion.")
        print("  These headers are free to add and should be standard.")
        print("=" * 60)
    else:
        print("[+] All required security headers are present. No vulnerability detected.")

except urllib.error.URLError as e:
    print(f"[!] Could not reach {TARGET}: {e.reason}")
except urllib.error.HTTPError as e:
    print(f"[!] HTTP error {e.code}: {e.reason}")
except Exception as e:
    print(f"[!] Unexpected error: {e}")
