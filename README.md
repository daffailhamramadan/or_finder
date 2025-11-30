# 🚀 Open Redirect Finder

**A powerful, automated Open Redirect vulnerability scanner.**

This tool is designed to detect Open Redirect vulnerabilities in web applications. It supports **Direct Scanning** of known URLs, **Automated Discovery** using `waymore`, and **Advanced DOM-based Detection** using `playwright`.

## ✨ Key Features

*   **🔍 Direct Scan**: Scan a single URL or a list of URLs for open redirects.
*   **🌐 Discovery Mode**: Automatically fetch URLs for a domain using `waymore`, filter them with `uro`, and scan them.
*   **🧠 Hybrid Scanning**: Combines fast HTTP requests with a headless browser (DOM) to detect both server-side and client-side redirects efficiently.
*   **🕷️ DOM Detection**: Uses Playwright to detect complex JavaScript-based redirects that standard scanners miss.
*   **🧹 Smart Filtering**: Built-in support for `uro` to deduplicate and filter uninteresting URLs (static files, etc.).
*   **⚡ Multithreaded**: Fast scanning with configurable thread count.
*   **🔔 Notifications**: Discord webhook support for real-time alerts.

---

## 🛠️ Prerequisites

*   **Python 3.x**
*   **[Waymore](https://github.com/xnl-h4ck3r/waymore)** (Required for Discovery Mode)
*   **[Uro](https://github.com/s0md3v/uro)** (Required for Discovery Mode)
*   **[Playwright](https://playwright.dev/)** (Required for DOM Scanner Mode)

---

## 📥 Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/daffailhamramadan/or_finder.git
    cd or_finder
    ```

2.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    pip install playwright
    playwright install chromium
    ```
    *Note: If you encounter an "externally-managed-environment" error, you may need to use `--break-system-packages` or install via your system package manager.*

3.  **Ensure External Tools are Installed:**
    Make sure `waymore` and `uro` are installed and available in your system PATH if you plan to use Discovery Mode.

---

## 🚀 Usage

### 1. Direct Mode (Scan Known URLs)
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

**With Filters (Recommended):**
Exclude static files (images, css, etc.) and keep specific extensions:
```bash
python3 or_finder.py -waymore -d example.com --exclude-static-files --extensions "php,asp,jsp"
```

### 3. Hybrid Mode (Fast + DOM Scan)
Use this mode to detect **DOM-based open redirects** (e.g., JavaScript redirects) that standard requests cannot find.
*   **Fast Scan First**: Checks for 3xx redirects and simple meta/JS redirects.
*   **DOM Scan Second**: Checks remaining URLs with a headless browser.

**Enable Hybrid Scanning:**
```bash
python3 or_finder.py -u "https://example.com/redirect?next=foo" --dom
```

**With Custom Timeout and Visible Browser:**
```bash
python3 or_finder.py -u "https://example.com/redirect?next=foo" --dom --dom-timeout 10000 --no-headless
```

---

## ⚙️ Arguments

### Target Arguments
| Flag | Description | Mode |
| :--- | :--- | :--- |
| `-u`, `--url` | Single URL to scan | Direct |
| `-l`, `--list` | File containing list of URLs to scan | Direct |
| `-d`, `--domain` | Single domain to fetch URLs for | Waymore |
| `-dL`, `--domain-list` | File containing list of domains | Waymore |

### Configuration
| Flag | Description | Default |
| :--- | :--- | :--- |
| `-p`, `--payload` | Payload URL to inject | `https://www.google.com` |
| `-t`, `--threads` | Number of threads | `10` |
| `--user-agent` | Custom User-Agent | Chrome/91.0... |
| `-o`, `--output` | Output file to save found redirects | None |
| `-v`, `--verbose` | Show verbose output | False |
| `--discord-webhook` | Discord Webhook URL for notifications | None |

### Waymore Integration
| Flag | Description |
| :--- | :--- |
| `-waymore` | Enable Waymore mode (requires `-d` or `-dL`) |
| `--extensions` | Comma-separated extensions to keep (passed to `uro -w`). Use "all" for no filter. |
| `--exclude-static-files` | Filter out common static files (passed to `uro -b`) |
| `--regex` | Regex pattern to exclude URLs |
| `--output-dir` | Directory to save results in Waymore mode (default: `results`) |

### DOM Scanner Arguments
| Flag | Description | Default |
| :--- | :--- | :--- |
| `--dom` | Enable DOM-based Open Redirect scanning (requires Playwright) | False |
| `--dom-timeout` | Timeout for DOM navigation in ms | `5000` |
| `--headless` | Run browser in headless mode | `True` |
| `--no-headless` | Run browser in visible mode | False |

---

## 📂 Output Structure (Waymore Mode)

When running in Waymore mode, the tool creates a directory for each domain inside the specified `--output-dir`.

Example structure for `python3 or_finder.py -waymore -d example.com --output-dir scans`:
```
scans/
└── example.com/
    ├── waymore.txt          # Raw URLs fetched by Waymore
    ├── filtered.txt         # URLs after filtering with Uro and Regex
    └── found_redirects.txt  # Vulnerable URLs found by the scanner
```

---

## 📝 Examples

**Full pipeline scan on a domain with DOM detection:**
```bash
python3 or_finder.py -waymore -d target.com --exclude-static-files --dom -t 20 -v
```

**Scan a list of domains with specific extensions:**
```bash
python3 or_finder.py -waymore -dL targets.txt --extensions "php,aspx" -o results.txt
```
