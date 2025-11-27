import argparse
import requests
import sys
import threading
import subprocess
import shutil
import re
from queue import Queue
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, Style, init

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
    parser.add_argument("-o", "--output", help="Output file to save found redirects")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    # Waymore integration arguments
    parser.add_argument("-waymore", action="store_true", help="Enable Waymore mode (requires -d or -dL)")
    parser.add_argument("--extensions", default="all", help="Comma-separated extensions to keep (passed to uro -w)")
    parser.add_argument("--exclude-files", action="store_true", help="Filter out common static files (passed to uro -b)")
    parser.add_argument("--regex", help="Regex pattern to exclude URLs")
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.waymore:
        if not (args.domain or args.domain_list):
            parser.error("-waymore mode requires -d/--domain or -dL/--domain-list")
    else:
        if not (args.url or args.list):
            parser.error("Direct mode requires -u/--url or -l/--list (or use -waymore with -d/-dL)")
            
    return args

def scan_url(url, payload, user_agent, verbose, output_file, lock):
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
                    elif verbose:
                         with lock:
                            print(f"{Fore.RED}[-] Redirected to {location} (Not payload){Style.RESET_ALL}")
                else:
                    if verbose:
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

def worker(queue, args, lock):
    while not queue.empty():
        url = queue.get()
        scan_url(url, args.payload, args.user_agent, args.verbose, args.output, lock)
        queue.task_done()

def fetch_urls_with_waymore(domains, args):
    if not shutil.which("waymore"):
        print(f"{Fore.RED}[!] waymore not found in PATH.{Style.RESET_ALL}")
        sys.exit(1)
    if not shutil.which("uro"):
        print(f"{Fore.RED}[!] uro not found in PATH.{Style.RESET_ALL}")
        sys.exit(1)

    all_urls = []
    
    for domain in domains:
        print(f"{Fore.BLUE}[*] Running waymore for: {domain}{Style.RESET_ALL}")
        
        # waymore command
        waymore_cmd = ["waymore", "-i", domain, "-mode", "U", "--stream"]
        
        # uro command
        uro_cmd = ["uro"]
        if args.exclude_files:
            static_exts = "jpg jpeg png gif bmp svg css js ico woff woff2 ttf eot pdf doc docx xls xlsx zip tar gz rar".split()
            uro_cmd.append("-b")
            uro_cmd.extend(static_exts)
        if args.extensions != "all":
            whitelist_exts = args.extensions.replace(",", " ").split()
            uro_cmd.append("-w")
            uro_cmd.extend(whitelist_exts)
            
        try:
            # Run waymore
            # Allow stderr to show progress/errors
            p1 = subprocess.Popen(waymore_cmd, stdout=subprocess.PIPE, text=True)
            
            # Run uro
            p2 = subprocess.Popen(uro_cmd, stdin=p1.stdout, stdout=subprocess.PIPE, text=True)
            p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits
            
            output, _ = p2.communicate()
            
            urls = output.splitlines()
            
            # Regex filter
            if args.regex:
                regex = re.compile(args.regex)
                urls = [u for u in urls if not regex.search(u)]
                
            print(f"{Fore.GREEN}[+] Found {len(urls)} URLs for {domain}{Style.RESET_ALL}")
            all_urls.extend(urls)
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error processing {domain}: {e}{Style.RESET_ALL}")

    return all_urls

def main():
    args = get_arguments()
    
    # Disable warnings for unverified HTTPS requests
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    
    target_urls = []
    
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
        
        target_urls = fetch_urls_with_waymore(domains, args)
        
    else:
        # Direct mode
        if args.url:
            target_urls.append(args.url)
        elif args.list:
            try:
                with open(args.list, "r") as f:
                    target_urls = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                print(f"{Fore.RED}[!] File not found: {args.list}{Style.RESET_ALL}")
                sys.exit(1)

    print(f"{Fore.BLUE}[*] Starting scan on {len(target_urls)} targets...{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Payload: {args.payload}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Threads: {args.threads}{Style.RESET_ALL}")

    queue = Queue()
    for url in target_urls:
        queue.put(url)

    lock = threading.Lock()
    threads = []
    
    for _ in range(min(args.threads, len(target_urls))):
        t = threading.Thread(target=worker, args=(queue, args, lock))
        t.start()
        threads.append(t)

    queue.join()
    
    for t in threads:
        t.join()

    print(f"{Fore.BLUE}[*] Scan complete.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
