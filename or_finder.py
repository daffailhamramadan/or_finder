import argparse
import requests
import sys
import threading
from queue import Queue
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Default User-Agent to avoid 403s
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

def get_arguments():
    parser = argparse.ArgumentParser(description="Open Redirect Finder CLI Tool")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Single URL to scan")
    group.add_argument("-l", "--list", help="File containing list of URLs to scan")
    
    parser.add_argument("-p", "--payload", default="https://www.google.com", help="Payload URL to inject (default: https://www.google.com)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--user-agent", default=DEFAULT_UA, help="Custom User-Agent")
    parser.add_argument("-o", "--output", help="Output file to save found redirects")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    return parser.parse_args()

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

def main():
    args = get_arguments()
    
    # Disable warnings for unverified HTTPS requests
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    
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
