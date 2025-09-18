import argparse
import sys
import requests
from urllib.parse import urljoin

def parse_arguments():
    parser = argparse.ArgumentParser(description="ReconX - Automated Reconnaissance Toolkit")
    parser.add_argument("-u", "--url", required=True, help="Target Base URL (e.g., https://target.com)")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist file")
    parser.add_argument("--status", default="200,301,302,401,403", help="Comma-separated status codes to filter (default: 200,301,302,401,403)")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--output", help="File to save results")
    return parser.parse_args()

def normalize_url(url):
    if not url.endswith('/'):
        return url + '/'
    return url

def fingerprint(target_url):
    print(f"[*] Fingerprinting {target_url}...")
    try:
        response = requests.get(target_url, timeout=10)
        headers = response.headers
        
        techs = []
        if 'Server' in headers:
            techs.append(f"Server: {headers['Server']}")
        if 'X-Powered-By' in headers:
            techs.append(f"X-Powered-By: {headers['X-Powered-By']}")
            
        print("[+] Detected Technologies:")
        for t in techs:
            print(f"  - {t}")
        
        # Check for specific keywords in headers for the "Presence of" requirement
        header_str = str(headers).lower()
        if 'php' in header_str: print("  - PHP detected (headers)")
        if 'asp.net' in header_str: print("  - ASP.NET detected (headers)")
        if 'node' in header_str: print("  - Node.js detected (headers)")
        if 'apache' in header_str: print("  - Apache detected (headers)")
        if 'nginx' in header_str: print("  - Nginx detected (headers)")

        print("-" * 40)
        
    except requests.RequestException as e:
        print(f"[!] Fingerprinting failed: {e}")
        sys.exit(1)

def scan_url(url, status_codes, output_file=None):
    try:
        response = requests.get(url, timeout=5, allow_redirects=False)
        if response.status_code in status_codes:
            size_kb = len(response.content) / 1024
            result = f"{url}  |  {response.status_code}  |  {size_kb:.2f}KB"
            print(result)
            
            if output_file:
                with open(output_file, "a") as f:
                    f.write(result + "\n")
                    
    except requests.RequestException:
        pass

def main():
    args = parse_arguments()
    base_url = normalize_url(args.url)
    wordlist_path = args.wordlist

    try:
        status_list = [int(s.strip()) for s in args.status.split(',')]
    except ValueError:
        print("[!] Invalid status codes provided.")
        sys.exit(1)

    try:
        with open(wordlist_path, 'r') as f:
            words = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Wordlist file not found: {wordlist_path}")
        sys.exit(1)
    
    fingerprint(base_url)
    
    print(f"[*] Starting enumeration on {base_url}")
    print(f"[*] Threads: {args.threads}")
    print(f"[*] Filtering Codes: {status_list}")
    print("-" * 40)

    if args.output:
        open(args.output, 'w').close()

    for word in words:
        target_url = urljoin(base_url, word)
        scan_url(target_url, status_list, args.output)

if __name__ == "__main__":
    main()
