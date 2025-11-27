# Open Redirect Finder

A powerful CLI tool to detect Open Redirect vulnerabilities. It supports direct scanning of URLs and automated URL discovery using `waymore` and `uro`.

## Features

- **Direct Scan**: Scan a single URL or a list of URLs for open redirects.
- **Discovery Mode**: Automatically fetch URLs for a domain using `waymore`, filter them with `uro`, and scan them.
- **Smart Filtering**: Built-in support for `uro` to deduplicate and filter uninteresting URLs (static files, etc.).
- **Multithreaded**: Fast scanning with configurable thread count.
- **Customizable**: Set custom payloads, user-agents, and regex filters.

## Prerequisites

- Python 3.x
- [Waymore](https://github.com/xnl-h4ck3r/waymore) (for Discovery Mode)
- [Uro](https://github.com/s0md3v/uro) (for Discovery Mode)

## Installation

1. Clone the repository.
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Ensure `waymore` and `uro` are installed and in your system PATH if you plan to use Discovery Mode.

## Usage

### 1. Direct Mode (Scan known URLs)

Use this mode if you already have a list of URLs to test.

**Scan a single URL:**
```bash
python3 or_finder.py -u "https://example.com/redirect?next=foo"
```

**Scan a list of URLs:**
```bash
python3 or_finder.py -l urls.txt -o results.txt
```

### 2. Waymore Mode (Discovery + Scan)

Use this mode to find URLs for a domain and immediately scan them.

**Scan a single domain:**
```bash
python3 or_finder.py -waymore -d example.com
```

**Scan a list of domains:**
```bash
python3 or_finder.py -waymore -dL domains.txt
```

**With Filters (Recommended):**
Exclude static files (images, css, etc.) and keep specific extensions:
```bash
python3 or_finder.py -waymore -d example.com --exclude-files --extensions "php,asp,jsp"
```

## Arguments

### Target Arguments
| Flag | Description | Mode |
|------|-------------|------|
| `-u`, `--url` | Single URL to scan | Direct |
| `-l`, `--list` | File containing list of URLs to scan | Direct |
| `-d`, `--domain` | Single domain to fetch URLs for | Waymore |
| `-dL`, `--domain-list` | File containing list of domains | Waymore |

### Configuration
| Flag | Description | Default |
|------|-------------|---------|
| `-p`, `--payload` | Payload URL to inject | `https://www.google.com` |
| `-t`, `--threads` | Number of threads | `10` |
| `--user-agent` | Custom User-Agent | Chrome/91.0... |
| `-o`, `--output` | Output file to save found redirects | None |
| `-v`, `--verbose` | Show verbose output | False |

### Waymore Integration
| Flag | Description |
|------|-------------|
| `-waymore` | Enable Waymore mode (requires `-d` or `-dL`) |
| `--extensions` | Comma-separated extensions to keep (passed to `uro -w`). Use "all" for no filter. |
| `--exclude-files` | Filter out common static files (passed to `uro -b`) |
| `--regex` | Regex pattern to exclude URLs |

## Examples

**Full pipeline scan on a domain:**
```bash
python3 or_finder.py -waymore -d target.com --exclude-files -t 20 -o found_redirects.txt -v
```

**Scan a list of domains with specific extensions:**
```bash
python3 or_finder.py -waymore -dL targets.txt --extensions "php,aspx" -o results.txt
```
