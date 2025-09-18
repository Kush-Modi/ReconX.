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
        print("-" * 40)
        
    except requests.RequestException as e:
        print(f"[!] Fingerprinting failed: {e}")
        sys.exit(1)

def main():
    args = parse_arguments()
    base_url = normalize_url(args.url)
    
    fingerprint(base_url)
    
    print(f"[*] Starting enumeration on {base_url}")
    print(f"[*] Threads: {args.threads}")

if __name__ == "__main__":
    main()
