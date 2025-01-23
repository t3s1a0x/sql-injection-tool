import requests
import argparse
import signal
import sys
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from colorama import Fore, Style, init
import urllib.parse

init(autoreset=True)

found_vulnerability = False

def handle_interrupt(signal, frame):
    print(f"\n\n{Fore.RED}[!] Process interrupted by user. Exiting...{Style.RESET_ALL}")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_interrupt)

def load_payloads(file_path):
    try:
        with open(file_path, "r") as file:
            payloads = file.read().splitlines()
        return payloads
    except Exception as e:
        print(f"{Fore.RED}[!] Error reading file: {e}{Style.RESET_ALL}")
        return []

def apply_waf_bypass(payload):
    techniques = [
        lambda p: urllib.parse.quote(p),
        lambda p: p.replace("'", "\\'"),
        lambda p: p.replace(" ", "/**/"),
        lambda p: p.replace("=", "LIKE"),
        lambda p: "'" + p + "'",
    ]

    bypassed_payloads = [payload]
    for technique in techniques:
        try:
            bypassed_payloads.append(technique(payload))
        except Exception as e:
            print(f"{Fore.YELLOW}[!] WAF bypass technique failed: {e}{Style.RESET_ALL}")

    return bypassed_payloads

def test_sql(payload, base_url, method, headers, data, proxy, progress_bar):
    global found_vulnerability
    if found_vulnerability:
        return

    waf_bypassed_payloads = apply_waf_bypass(payload)

    for bypassed_payload in waf_bypassed_payloads:
        try:
            if method == "GET":
                url = base_url + requests.utils.quote(bypassed_payload)
                response = requests.get(url, headers=headers, proxies=proxy, timeout=10)
            else:
                post_data = {k: (v + bypassed_payload if v == "<inject>" else v) for k, v in data.items()}
                response = requests.post(base_url, data=post_data, headers=headers, proxies=proxy, timeout=10)

            sql_errors = [
                "You have an error in your SQL syntax",
                "Warning: mysql_fetch",
                "Unclosed quotation mark after the character string",
                "SQLSTATE",
                "MySQL server version for the right syntax",
                "unterminated quoted string",
                "ORA-00933: SQL command not properly ended"
            ]
            if any(error in response.text for error in sql_errors):
                found_vulnerability = True
                progress_bar.close()
                print(f"\n\n{Fore.GREEN}[!] SQL Injection Vulnerability Detected!{Style.RESET_ALL}")
                print(f"{Fore.CYAN}    [+] Payload: {Fore.YELLOW}{bypassed_payload}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}    [+] Affected URL: {Fore.YELLOW}{response.url}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}    [+] HTTP Status Code: {Fore.YELLOW}{response.status_code}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}    [+] Response Length: {Fore.YELLOW}{len(response.text)} bytes{Style.RESET_ALL}")
                print(f"\n{Fore.RED}[!] Stopping further testing as vulnerability was detected.{Style.RESET_ALL}")
                return
        except Exception as e:
            print(f"\n{Fore.RED}[!] Error testing payload '{bypassed_payload}': {e}{Style.RESET_ALL}")
        finally:
            progress_bar.update(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced SQL Injection Testing Tool - Created by Ali Qassem @e5t3hb4r47")
    parser.add_argument("-u", "--url", required=True, help="The base URL to test, e.g., 'https://example.com/page?id='")
    parser.add_argument("-p", "--payload", required=True, help="The file containing SQL payloads to test")
    parser.add_argument("--method", choices=["GET", "POST"], default="GET", help="HTTP method to use (default: GET)")
    parser.add_argument("--data", help="POST data for testing (use '<inject>' to specify injection points)")
    parser.add_argument("--headers", help="Custom headers in 'Key: Value' format (comma-separated)")
    parser.add_argument("--proxy", help="Proxy server to use (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--retries", type=int, default=3, help="Number of retries on request failure (default: 3)")

    args = parser.parse_args()

    base_url = args.url
    payload_file = args.payload
    method = args.method
    post_data = {k: v for k, v in (item.split('=') for item in args.data.split('&'))} if args.data else {}
    headers = {k.strip(): v.strip() for k, v in (header.split(':') for header in args.headers.split(','))} if args.headers else {}
    proxy = {"http": args.proxy, "https": args.proxy} if args.proxy else None

    payloads = load_payloads(payload_file)
    if not payloads:
        print(f"{Fore.RED}[!] No payloads found. Exiting...{Style.RESET_ALL}")
        sys.exit(1)

    print(f"{Fore.MAGENTA}[#] Advanced SQL Injection Testing Tool - Created by Ali Qassem @e5t3hb4r47 [#]{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Loaded {len(payloads)} payloads from {payload_file}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Starting SQL Injection tests...\n{Style.RESET_ALL}")

    with tqdm(total=len(payloads), desc="Testing Payloads", unit="payload") as progress_bar:
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(lambda payload: test_sql(payload, base_url, method, headers, post_data, proxy, progress_bar), payloads)

    if not found_vulnerability:
        print(f"\n{Fore.YELLOW}[-] No SQL Injection vulnerabilities detected after testing all payloads.{Style.RESET_ALL}")
