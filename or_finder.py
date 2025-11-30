import argparse
import requests
import configparser
import sys
import threading
import subprocess
import shutil
import re
import os
import asyncio
from queue import Queue
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, Style, init

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# Initialize colorama
init(autoreset=True)

# Default User-Agent to avoid 403s
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

def get_arguments():
    parser = argparse.ArgumentParser(description="Open Redirect Finder CLI Tool")
    
    # Target arguments
    target_group = parser.add_argument_group("Target Arguments")
    target_group.add_argument("-u", "--url", help="Single URL to scan (Direct mode)")
    target_group.add_argument("-l", "--list", help="File containing list of URLs to scan (Direct mode)")
    target_group.add_argument("-d", "--domain", help="Single domain to fetch URLs for (Waymore mode)")
    target_group.add_argument("-dL", "--domain-list", help="File containing list of domains to fetch URLs for (Waymore mode)")
    
    # Configuration arguments
    parser.add_argument("-p", "--payload", default="https://www.google.com", help="Payload URL to inject (default: https://www.google.com)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--user-agent", default=DEFAULT_UA, help="Custom User-Agent")
    parser.add_argument("-o", "--output", help="Output file to save found redirects (Direct mode)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--discord-webhook", help="Discord Webhook URL for notifications")
    
    # Waymore integration arguments
    parser.add_argument("-waymore", action="store_true", help="Enable Waymore mode (requires -d or -dL)")
    parser.add_argument("--extensions", default="all", help="Comma-separated extensions to keep (passed to uro -w)")
    parser.add_argument("--exclude-static-files", action="store_true", help="Filter out common static files (passed to uro -b)")
    parser.add_argument("--regex", help="Regex pattern to exclude URLs")
    parser.add_argument("--output-dir", default="results", help="Directory to save results in Waymore mode (default: results)")
    
    # DOM Scanner arguments
    parser.add_argument("--dom", action="store_true", help="Enable DOM-based Open Redirect scanning (slower, requires Playwright)")
    parser.add_argument("--dom-timeout", type=int, default=5000, help="Timeout for DOM navigation in ms (default: 5000)")
    parser.add_argument("--headless", action="store_true", default=True, help="Run browser in headless mode (default: True)")
    parser.add_argument("--no-headless", action="store_false", dest="headless", help="Run browser in visible mode")

    args = parser.parse_args()
    
    # Validate arguments
    if args.waymore:
        if not (args.domain or args.domain_list):
            parser.error("-waymore mode requires -d/--domain or -dL/--domain-list")
    else:
        if not (args.url or args.list):
            parser.error("Direct mode requires -u/--url or -l/--list (or use -waymore with -d/-dL)")
    
    if args.dom and not PLAYWRIGHT_AVAILABLE:
        print(f"{Fore.RED}[!] Playwright is not installed. Please install it to use --dom.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    pip install playwright{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    playwright install chromium{Style.RESET_ALL}")
        sys.exit(1)
            
    return args

def send_discord_notification(webhook_url, message):
    if not webhook_url:
        return
    
    data = {
        "content": message
    }
    try:
        requests.post(webhook_url, json=data)
    except Exception as e:
        print(f"{Fore.RED}[!] Error sending Discord notification: {e}{Style.RESET_ALL}")

def check_client_side_redirect(response_text, payload):
    """
    Checks for client-side redirects (Meta Refresh, JS) in the response body.
    """
    # Check for Meta Refresh
    # <meta http-equiv="refresh" content="0; url=http://example.com/">
    meta_refresh_pattern = re.compile(r'<meta[^>]*http-equiv=["\']?refresh["\']?[^>]*content=["\']?[^"\']*url=([^"\'>]+)["\']?', re.IGNORECASE)
    match = meta_refresh_pattern.search(response_text)
    if match:
        url = match.group(1)
        if payload in url:
            return url, "Meta Refresh"
            
    # Check for JavaScript redirects
    # window.location = "..."
    # window.location.href = "..."
    # window.location.replace("...")
    # self.location = ...
    # top.location = ...
    # document.location = ...
    
    js_patterns = [
        r'(?:window|self|top|document)\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
        r'(?:window|self|top|document)\.location\.replace\s*\(\s*["\']([^"\']+)["\']\s*\)'
    ]
    
    for pattern in js_patterns:
        matches = re.finditer(pattern, response_text, re.IGNORECASE)
        for match in matches:
            url = match.group(1)
            if payload in url:
                return url, "JavaScript Redirect"
                
    return None, None

def scan_url(url, payload, user_agent, verbose, output_file, lock, discord_webhook=None, vulnerable_set=None):
    try:
        # Parse the URL
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # If no parameters, nothing to fuzz (unless we append, but let's stick to replacing for now)
        if not query_params:
            if verbose:
                with lock:
                    print(f"{Fore.YELLOW}[*] No parameters found in {url}{Style.RESET_ALL}")
            return

        # Fuzz each parameter
        for param in query_params:
            # Create a copy of params to modify
            fuzzed_params = query_params.copy()
            fuzzed_params[param] = [payload]
            
            # Reconstruct URL
            new_query = urlencode(fuzzed_params, doseq=True)
            fuzzed_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            
            if verbose:
                with lock:
                    print(f"[*] Testing: {fuzzed_url}")

            try:
                # Send request
                # We don't follow redirects automatically to check the Location header of the first response
                response = requests.get(fuzzed_url, headers={"User-Agent": user_agent}, allow_redirects=False, timeout=10, verify=False)
                
                # Check for Open Redirect
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    
                    if location == payload or (payload in location and location.startswith(payload)):
                        with lock:
                            print(f"{Fore.GREEN}[+] OPEN REDIRECT FOUND: {fuzzed_url}{Style.RESET_ALL}")
                            print(f"    {Fore.CYAN}Redirects to: {location}{Style.RESET_ALL}")
                            
                            if output_file:
                                with open(output_file, "a") as f:
                                    f.write(f"{fuzzed_url}\n")
                            
                            if discord_webhook:
                                message = f"**Open Redirect Found!**\nURL: {fuzzed_url}\nRedirects to: {location}"
                                send_discord_notification(discord_webhook, message)
                            
                            if vulnerable_set is not None:
                                vulnerable_set.add(url)
                    elif verbose:
                         with lock:
                            print(f"{Fore.RED}[-] Redirected to {location} (Not payload){Style.RESET_ALL}")
                
                else:
                    # Check for Refresh Header (can be 200 OK)
                    refresh_header = response.headers.get('Refresh', '')
                    if refresh_header and 'url=' in refresh_header.lower():
                        url_part = refresh_header.split('url=', 1)[1]
                        if payload in url_part:
                            with lock:
                                print(f"{Fore.GREEN}[+] OPEN REDIRECT FOUND (Refresh Header): {fuzzed_url}{Style.RESET_ALL}")
                                print(f"    {Fore.CYAN}Redirects to: {url_part}{Style.RESET_ALL}")
                                
                                if output_file:
                                    with open(output_file, "a") as f:
                                        f.write(f"{fuzzed_url}\n")
                                
                                if discord_webhook:
                                    message = f"**Open Redirect Found (Refresh Header)!**\nURL: {fuzzed_url}\nRedirects to: {url_part}"
                                    send_discord_notification(discord_webhook, message)
                                
                                if vulnerable_set is not None:
                                    vulnerable_set.add(url)
                            return # Found, stop checking this response

                    # Check for Client-Side Redirects (Meta/JS)
                    redirect_url, redirect_type = check_client_side_redirect(response.text, payload)
                    if redirect_url:
                        with lock:
                            print(f"{Fore.GREEN}[+] OPEN REDIRECT FOUND ({redirect_type}): {fuzzed_url}{Style.RESET_ALL}")
                            print(f"    {Fore.CYAN}Redirects to: {redirect_url}{Style.RESET_ALL}")
                            
                            if output_file:
                                with open(output_file, "a") as f:
                                    f.write(f"{fuzzed_url}\n")
                            
                            if discord_webhook:
                                message = f"**Open Redirect Found ({redirect_type})!**\nURL: {fuzzed_url}\nRedirects to: {redirect_url}"
                                send_discord_notification(discord_webhook, message)
                            
                            if vulnerable_set is not None:
                                vulnerable_set.add(url)
                    
                    elif verbose:
                        with lock:
                            print(f"{Fore.RED}[-] Status Code: {response.status_code}{Style.RESET_ALL}")

            except requests.exceptions.RequestException as e:
                if verbose:
                    with lock:
                        print(f"{Fore.RED}[!] Error scanning {fuzzed_url}: {e}{Style.RESET_ALL}")

    except Exception as e:
        if verbose:
            with lock:
                print(f"{Fore.RED}[!] Error parsing {url}: {e}{Style.RESET_ALL}")

async def scan_dom_redirect(context, url, payload, verbose, output_file, lock, discord_webhook=None, timeout=5000):
    page = await context.new_page()
    try:
        # Parse the URL and fuzz parameters
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        if not query_params:
            if verbose:
                print(f"{Fore.YELLOW}[*] No parameters found in {url}{Style.RESET_ALL}")
            await page.close()
            return

        for param in query_params:
            fuzzed_params = query_params.copy()
            fuzzed_params[param] = [payload]
            new_query = urlencode(fuzzed_params, doseq=True)
            fuzzed_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            
            if verbose:
                print(f"[*] DOM Testing: {fuzzed_url}")

            try:
                # Navigate to the fuzzed URL
                # We use wait_until='domcontentloaded' to be faster, but networkidle might be safer for complex redirects
                await page.goto(fuzzed_url, wait_until='domcontentloaded', timeout=timeout)
                
                # Wait for potential redirect
                # We check if the page URL eventually starts with the payload
                try:
                    # Wait for the URL to change to the payload
                    # This handles cases where the redirect happens after some JS execution
                    await page.wait_for_url(lambda u: u.startswith(payload) or payload in u, timeout=timeout)
                    
                    final_url = page.url
                    if payload in final_url:
                         with lock:
                            print(f"{Fore.GREEN}[+] DOM OPEN REDIRECT FOUND: {fuzzed_url}{Style.RESET_ALL}")
                            print(f"    {Fore.CYAN}Redirects to: {final_url}{Style.RESET_ALL}")
                            
                            if output_file:
                                with open(output_file, "a") as f:
                                    f.write(f"{fuzzed_url}\n")
                            
                            if discord_webhook:
                                message = f"**DOM Open Redirect Found!**\nURL: {fuzzed_url}\nRedirects to: {final_url}"
                                send_discord_notification(discord_webhook, message)
                except Exception:
                    # Timeout waiting for redirect, check current URL one last time
                    final_url = page.url
                    if payload in final_url and final_url.startswith(payload):
                         with lock:
                            print(f"{Fore.GREEN}[+] DOM OPEN REDIRECT FOUND: {fuzzed_url}{Style.RESET_ALL}")
                            print(f"    {Fore.CYAN}Redirects to: {final_url}{Style.RESET_ALL}")
                            
                            if output_file:
                                with open(output_file, "a") as f:
                                    f.write(f"{fuzzed_url}\n")
                            
                            if discord_webhook:
                                message = f"**DOM Open Redirect Found!**\nURL: {fuzzed_url}\nRedirects to: {final_url}"
                                send_discord_notification(discord_webhook, message)
                    elif verbose:
                        print(f"{Fore.RED}[-] No redirect detected for {fuzzed_url}{Style.RESET_ALL}")

            except Exception as e:
                if verbose:
                    print(f"{Fore.RED}[!] Error scanning {fuzzed_url}: {e}{Style.RESET_ALL}")

    except Exception as e:
        if verbose:
            print(f"{Fore.RED}[!] Error parsing {url}: {e}{Style.RESET_ALL}")
    finally:
        await page.close()

async def worker_dom(queue, context, args, lock, output_file):
    while not queue.empty():
        url = await queue.get()
        await scan_dom_redirect(context, url, args.payload, args.verbose, output_file, lock, args.discord_webhook, args.dom_timeout)
        queue.task_done()

async def run_scan_dom(target_urls, args, output_file):
    print(f"{Fore.BLUE}[*] Starting DOM scan on {len(target_urls)} targets...{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Payload: {args.payload}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Threads (Browsers): {args.threads}{Style.RESET_ALL}")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=args.headless)
        context = await browser.new_context(user_agent=args.user_agent, ignore_https_errors=True)
        
        queue = asyncio.Queue()
        for url in target_urls:
            queue.put_nowait(url)
            
        lock = threading.Lock() # Still use threading lock for print safety, though async is single-threaded mostly
        
        tasks = []
        for _ in range(min(args.threads, len(target_urls))):
            task = asyncio.create_task(worker_dom(queue, context, args, lock, output_file))
            tasks.append(task)
            
        await queue.join()
        
        for task in tasks:
            task.cancel()
            
        await browser.close()

    print(f"{Fore.BLUE}[*] DOM Scan complete.{Style.RESET_ALL}")

def worker(queue, args, lock, output_file, vulnerable_set):
    while not queue.empty():
        url = queue.get()
        scan_url(url, args.payload, args.user_agent, args.verbose, output_file, lock, args.discord_webhook, vulnerable_set)
        queue.task_done()

def run_scan(target_urls, args, output_file):
    print(f"{Fore.BLUE}[*] Starting scan on {len(target_urls)} targets...{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Payload: {args.payload}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Threads: {args.threads}{Style.RESET_ALL}")

    queue = Queue()
    for url in target_urls:
        queue.put(url)

    lock = threading.Lock()
    vulnerable_set = set()
    threads = []
    
    for _ in range(min(args.threads, len(target_urls))):
        t = threading.Thread(target=worker, args=(queue, args, lock, output_file, vulnerable_set))
        t.start()
        threads.append(t)

    queue.join()
    
    for t in threads:
        t.join()

    print(f"{Fore.BLUE}[*] Scan complete.{Style.RESET_ALL}")
    return vulnerable_set

def process_domain_waymore(domain, args):
    if not shutil.which("waymore"):
        print(f"{Fore.RED}[!] waymore not found in PATH.{Style.RESET_ALL}")
        sys.exit(1)
    if not shutil.which("uro"):
        print(f"{Fore.RED}[!] uro not found in PATH.{Style.RESET_ALL}")
        sys.exit(1)

    # Create domain directory
    domain_dir = os.path.join(args.output_dir, domain)
    os.makedirs(domain_dir, exist_ok=True)
    
    raw_file = os.path.join(domain_dir, "waymore.txt")
    filtered_file = os.path.join(domain_dir, "filtered.txt")
    
    print(f"{Fore.BLUE}[*] Processing domain: {domain}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Output directory: {domain_dir}{Style.RESET_ALL}")
    
    # waymore command
    print(f"{Fore.BLUE}[*] Running waymore...{Style.RESET_ALL}")
    waymore_cmd = ["waymore", "-i", domain, "-mode", "U", "--stream"]
    
    # uro command
    uro_cmd = ["uro"]
    if args.exclude_static_files:
        static_exts = "jpg jpeg png gif bmp svg css js ico woff woff2 ttf eot pdf doc docx xls xlsx zip tar gz rar".split()
        uro_cmd.append("-b")
        uro_cmd.extend(static_exts)
    if args.extensions != "all":
        whitelist_exts = args.extensions.replace(",", " ").split()
        uro_cmd.append("-w")
        uro_cmd.extend(whitelist_exts)
        
    try:
        # Run waymore and save raw output
        with open(raw_file, "w") as f_raw:
            p1 = subprocess.Popen(waymore_cmd, stdout=subprocess.PIPE, text=True)
            
            # Run waymore and save raw output to file, then read it for uro

            
            stdout, _ = p1.communicate()
            f_raw.write(stdout)
            
        # Run uro on raw file
        print(f"{Fore.BLUE}[*] Running uro...{Style.RESET_ALL}")
        with open(raw_file, "r") as f_in, open(filtered_file, "w") as f_out:
            p2 = subprocess.Popen(uro_cmd, stdin=f_in, stdout=subprocess.PIPE, text=True)
            output, _ = p2.communicate()
            
            # Regex filter
            urls = output.splitlines()
            if args.regex:
                regex = re.compile(args.regex)
                urls = [u for u in urls if not regex.search(u)]
                
            # Write filtered URLs to file
            for url in urls:
                f_out.write(url + "\n")
                
        print(f"{Fore.GREEN}[+] Found {len(urls)} URLs for {domain}{Style.RESET_ALL}")
        return urls, domain_dir
        
    except Exception as e:
        print(f"{Fore.RED}[!] Error processing {domain}: {e}{Style.RESET_ALL}")
        return [], domain_dir

def main():
    try:
        args = get_arguments()

        # Load config
        config = configparser.ConfigParser()
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.ini')
        if os.path.exists(config_path):
            config.read(config_path)
            if not args.discord_webhook and 'discord' in config and 'webhook_url' in config['discord']:
                 args.discord_webhook = config['discord']['webhook_url']
        
        # Disable warnings for unverified HTTPS requests
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        
        if args.waymore:
            domains = []
            if args.domain:
                domains.append(args.domain)
            if args.domain_list:
                try:
                    with open(args.domain_list, "r") as f:
                        domains.extend([line.strip() for line in f if line.strip()])
                except FileNotFoundError:
                    print(f"{Fore.RED}[!] File not found: {args.domain_list}{Style.RESET_ALL}")
                    sys.exit(1)
            
            # Process each domain
            for domain in domains:
                urls, domain_dir = process_domain_waymore(domain, args)
                if urls:
                    output_file = os.path.join(domain_dir, "found_redirects.txt")
                    
                    # Always run fast scan first
                    vulnerable_set = run_scan(urls, args, output_file)
                    
                    if args.dom:
                        # Filter out URLs that were already found to avoid redundant slow DOM scans
                        dom_urls = [u for u in urls if u not in vulnerable_set]
                        if dom_urls:
                            asyncio.run(run_scan_dom(dom_urls, args, output_file))
            
        else:
            # Direct mode
            target_urls = []
            if args.url:
                target_urls.append(args.url)
            elif args.list:
                try:
                    with open(args.list, "r") as f:
                        target_urls = [line.strip() for line in f if line.strip()]
                except FileNotFoundError:
                    print(f"{Fore.RED}[!] File not found: {args.list}{Style.RESET_ALL}")
                    sys.exit(1)
            
            # Always run fast scan first
            vulnerable_set = run_scan(target_urls, args, args.output)

            if args.dom:
                # Filter out URLs that were already found
                dom_urls = [u for u in target_urls if u not in vulnerable_set]
                if dom_urls:
                    asyncio.run(run_scan_dom(dom_urls, args, args.output))
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user (Ctrl+C). Exiting gracefully...{Style.RESET_ALL}")
        sys.exit(0)

if __name__ == "__main__":
    main()
