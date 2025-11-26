# Open Redirect Finder

A simple CLI tool to detect Open Redirect vulnerabilities in URLs.

## Installation

1. Clone the repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Scan a single URL
```bash
python or_finder.py -u "https://example.com/redirect?url=test"
```

### Scan a list of URLs
```bash
python or_finder.py -l urls.txt
```

### Options
- `-p, --payload`: Custom payload URL (default: https://www.google.com)
- `-t, --threads`: Number of threads (default: 10)
- `-o, --output`: Save results to a file
- `-v, --verbose`: Show verbose output
