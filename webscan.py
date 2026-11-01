#!/usr/bin/env python3
"""
webscan - a small, dependency-free web security scanner.

Checks: HTTPS/TLS, security headers, cookie flags, information leaks,
and commonly exposed files.

ONLY scan sites you own or have written permission to test.

Usage:
    python webscan.py example.com
    python webscan.py https://example.com --json -o report.json
"""

import argparse
import json
import socket
import ssl
import sys
import time
from urllib.error import HTTPError
from urllib.parse import urlparse, urljoin
from urllib.request import Request, urlopen

TIMEOUT = 10
USER_AGENT = "webscan/1.0 (security self-assessment)"
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# header -> (severity, fix)
SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "medium",
        "Add HSTS, e.g. 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
    ),
    "Content-Security-Policy": (
        "medium",
        "Define a Content-Security-Policy to limit where scripts and resources can load from.",
    ),
    "X-Content-Type-Options": ("low", "Set 'X-Content-Type-Options: nosniff'."),
    "X-Frame-Options": (
        "low",
        "Set 'X-Frame-Options: DENY' (or SAMEORIGIN), or use CSP frame-ancestors.",
    ),
    "Referrer-Policy": (
        "low",
        "Set a Referrer-Policy such as 'strict-origin-when-cross-origin'.",
    ),
    "Permissions-Policy": (
        "low",
        "Set a Permissions-Policy to disable browser features you don't use.",
    ),
}

# path -> (severity, substring that must appear in the body to count as a real hit)
EXPOSED_PATHS = {
    "/.env": ("high", "="),
    "/.git/HEAD": ("high", "ref:"),
    "/.git/config": ("high", "[core]"),
    "/wp-config.php.bak": ("high", "DB_"),
    "/phpinfo.php": ("medium", "phpinfo"),
    "/server-status": ("medium", "Apache"),
    "/backup.zip": ("high", None),
    "/backup.sql": ("high", None),
    "/.DS_Store": ("low", None),
    "/robots.txt": ("info", "llow"),
}


def finding(severity, title, detail, fix=""):
    return {"severity": severity, "title": title, "detail": detail, "fix": fix}


def fetch(url, method="GET", limit=65536):
    """Return (status, headers, body_bytes, final_url). Raises on network errors."""
    req = Request(url, method=method, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read(limit) if method == "GET" else b""
            return resp.status, resp.headers, body, resp.geturl()
    except HTTPError as err:
        return err.code, err.headers, b"", url


def check_https(url):
    if urlparse(url).scheme != "https":
        return [
            finding(
                "medium",
                "Site is served over plain HTTP",
                f"{url} does not use HTTPS.",
                "Serve the site over HTTPS and redirect all HTTP traffic to it.",
            )
        ]
    return []


def check_tls(host, port=443):
    results = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                version = tls.version()
    except ssl.SSLCertVerificationError as err:
        return [
            finding(
                "high",
                "TLS certificate failed verification",
                str(err),
                "Install a valid certificate from a trusted CA that matches the hostname.",
            )
        ]
    except (ssl.SSLError, OSError) as err:
        return [finding("medium", "Could not complete TLS handshake", str(err))]

    results.append(finding("info", "TLS connection", f"Negotiated {version}."))
    if version in ("TLSv1", "TLSv1.1"):
        results.append(
            finding(
                "medium",
                "Outdated TLS version",
                f"Server negotiated {version}.",
                "Disable TLS 1.0/1.1 and allow only TLS 1.2 and 1.3.",
            )
        )

    expires = ssl.cert_time_to_seconds(cert["notAfter"])
    days_left = int((expires - time.time()) // 86400)
    if days_left < 0:
        results.append(finding("high", "Certificate expired", f"Expired {-days_left} days ago.", "Renew the certificate."))
    elif days_left < 14:
        results.append(finding("medium", "Certificate expires soon", f"{days_left} days left.", "Renew the certificate."))
    elif days_left < 30:
        results.append(finding("low", "Certificate expires within 30 days", f"{days_left} days left.", "Plan a renewal."))
    else:
        results.append(finding("info", "Certificate validity", f"{days_left} days until expiry."))
    return results


def check_headers(headers, is_https):
    results = []
    lowered = {k.lower(): v for k, v in headers.items()}
    csp = lowered.get("content-security-policy", "")

    for name, (severity, fix) in SECURITY_HEADERS.items():
        key = name.lower()
        if key == "strict-transport-security" and not is_https:
            continue
        if key == "x-frame-options" and "frame-ancestors" in csp:
            continue
        if key not in lowered:
            results.append(finding(severity, f"Missing header: {name}", f"{name} was not sent.", fix))

    server = lowered.get("server", "")
    if any(ch.isdigit() for ch in server):
        results.append(
            finding(
                "low",
                "Server version disclosed",
                f"Server header reveals: {server}",
                "Hide version details from the Server header.",
            )
        )
    if "x-powered-by" in lowered:
        results.append(
            finding(
                "low",
                "Technology disclosed via X-Powered-By",
                f"X-Powered-By: {lowered['x-powered-by']}",
                "Remove the X-Powered-By header.",
            )
        )
    return results


def check_cookies(headers, is_https):
    results = []
    for raw in headers.get_all("Set-Cookie") or []:
        name = raw.split("=", 1)[0].strip()
        attrs = raw.lower()
        if is_https and "secure" not in attrs:
            results.append(finding("medium", f"Cookie '{name}' missing Secure flag", raw.split(";")[0] + "; ...", "Add the Secure attribute."))
        if "httponly" not in attrs:
            results.append(finding("medium", f"Cookie '{name}' missing HttpOnly flag", "Scripts can read this cookie.", "Add the HttpOnly attribute."))
        if "samesite" not in attrs:
            results.append(finding("low", f"Cookie '{name}' missing SameSite", "No SameSite attribute set.", "Add SameSite=Lax or Strict."))
    return results


def check_exposed_files(base_url):
    results = []
    for path, (severity, marker) in EXPOSED_PATHS.items():
        url = urljoin(base_url, path)
        try:
            status, _, body, _ = fetch(url)
        except Exception:
            continue
        if status != 200:
            continue
        text = body.decode("utf-8", errors="ignore")
        if marker is not None and marker not in text:
            continue  # likely a soft-404 or unrelated page
        if severity == "info":
            results.append(finding("info", f"Found {path}", url))
        else:
            results.append(
                finding(
                    severity,
                    f"Exposed file: {path}",
                    f"{url} is publicly accessible.",
                    "Remove the file from the web root or block access to it in your server config.",
                )
            )
    return results


def scan(target):
    parsed = urlparse(target)
    host = parsed.hostname
    is_https = parsed.scheme == "https"
    findings = check_https(target)

    status, headers, _, final_url = fetch(target)
    final = urlparse(final_url)
    is_https = final.scheme == "https"
    findings.append(finding("info", "Response", f"HTTP {status} from {final_url}"))

    if is_https:
        findings += check_tls(final.hostname, final.port or 443)
    findings += check_headers(headers, is_https)
    findings += check_cookies(headers, is_https)
    findings += check_exposed_files(final_url)
    return sorted(findings, key=lambda f: SEVERITY_ORDER[f["severity"]])


def print_report(target, findings):
    print(f"\nwebscan report for {target}\n" + "=" * 60)
    for f in findings:
        print(f"[{f['severity'].upper():6}] {f['title']}")
        if f["detail"]:
            print(f"         {f['detail']}")
        if f["fix"]:
            print(f"         Fix: {f['fix']}")
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}
    print("=" * 60)
    print("Summary: " + ", ".join(f"{n} {s}" for s, n in counts.items()))


def main():
    parser = argparse.ArgumentParser(description="Simple web security scanner.")
    parser.add_argument("target", help="URL or hostname to scan")
    parser.add_argument("--json", action="store_true", help="output JSON instead of text")
    parser.add_argument("-o", "--output", help="write the report to this file")
    parser.add_argument("--yes", action="store_true", help="confirm you own or have permission to test the target")
    args = parser.parse_args()

    target = args.target if "://" in args.target else f"https://{args.target}"

    if not args.yes:
        answer = input("Do you own this site or have written permission to test it? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            print("Aborted. Only scan sites you are authorized to test.")
            return 2

    try:
        findings = scan(target)
    except Exception as err:
        print(f"Scan failed: {err}", file=sys.stderr)
        return 2

    if args.json:
        output = json.dumps({"target": target, "findings": findings}, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(output)
            print(f"Report written to {args.output}")
        else:
            print(output)
    else:
        print_report(target, findings)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump({"target": target, "findings": findings}, fh, indent=2)
            print(f"JSON report written to {args.output}")

    return 1 if any(f["severity"] in ("high", "medium") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
