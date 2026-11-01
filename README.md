# SiteSentry

**A lightweight command-line web security scanner that checks your site's HTTPS, headers, cookies and exposed files, then tells you how to fix what it finds.**

> ⚠️ **Legal notice:** Only scan websites you own or have written permission to test. Unauthorized scanning may be illegal in your country.

---

## Features

- **HTTPS and TLS:** detects plain-HTTP sites, invalid or expiring certificates, and outdated TLS versions
- **Security headers:** HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
- **Cookie flags:** missing `Secure`, `HttpOnly` and `SameSite`
- **Information leaks:** server version banners and `X-Powered-By`
- **Exposed files:** `.env`, `.git`, backups, `phpinfo.php` and more (content-checked to reduce false positives)
- **Clear reports:** severity levels (high, medium, low, info), a fix suggestion for each finding, and optional JSON output
- **No dependencies:** uses only the Python standard library

## Requirements

- Python **3.8 or newer**
- No third-party packages (see `requirements.txt`)

## Installation

### Linux / macOS

```bash
# 1. Get the code
git clone https://github.com/dharmpatel1857-cmyk/SiteSentry.git
cd SiteSentry

# 2. (Optional but recommended) create a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install requirements
pip install -r requirements.txt
```

### Windows (PowerShell)

```powershell
# 1. Get the code
git clone https://github.com/dharmpatel1857-cmyk/SiteSentry.git
cd SiteSentry

# 2. (Optional but recommended) create a virtual environment
python -m venv venv
venv\Scripts\Activate.ps1

# 3. Install requirements
pip install -r requirements.txt
```

### Without Git

Download `webscan.py` and run it directly. No installation step is needed.

## Usage

```bash
# Basic scan (you will be asked to confirm you have permission)
python webscan.py example.com

# Full URL
python webscan.py https://example.com

# Skip the permission prompt (only if you are authorized to scan the target)
python webscan.py example.com --yes

# JSON output
python webscan.py example.com --yes --json

# Save the report to a file
python webscan.py example.com --yes --json -o report.json
```

### Options

| Option | Description |
| --- | --- |
| `target` | URL or hostname to scan |
| `--json` | Output the report as JSON |
| `-o`, `--output FILE` | Write the report to a file |
| `--yes` | Confirm you own the target or have permission to test it |
| `-h`, `--help` | Show help |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan finished with no high or medium findings |
| `1` | Scan finished with at least one high or medium finding |
| `2` | Scan failed or was cancelled |

These make SiteSentry easy to use in CI pipelines.

## Example output

```
webscan report for https://example.com
============================================================
[MEDIUM] Missing header: Content-Security-Policy
         Content-Security-Policy was not sent.
         Fix: Define a Content-Security-Policy to limit where scripts and resources can load from.
[LOW   ] Server version disclosed
         Server header reveals: nginx/1.18.0
         Fix: Hide version details from the Server header.
============================================================
Summary: 0 high, 1 medium, 1 low, 2 info
```

## Roadmap

- Scan multiple URLs from a file
- HTML report export
- CORS, `security.txt` and mixed-content checks

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Disclaimer

This tool is provided for educational and defensive security purposes. The authors are not responsible for misuse or for any damage caused by its use.

## License

Released under the [MIT License](LICENSE).
