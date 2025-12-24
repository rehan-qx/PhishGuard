import requests
import socket
import ssl
import re
import whois
import datetime
from urllib.parse import urlparse
from colorama import Fore, Style, init

# Initialize Colors
init(autoreset=True)

def get_banner():
    print(Fore.CYAN + """
    ==========================================================
      SENTINEL-X PHISHGUARD (v1.0) - PHISHING DETECTION
      [ SSL Analysis | Redirect Tracking | Port Scan | Age ]
    ==========================================================
    """ + Style.RESET_ALL)

# --- STEP 1: REDIRECT ANALYSIS ---
def analyze_redirects(url):
    print(Fore.YELLOW + "\n[+] Phase 1: Tracing Redirect Chain...")
    try:
        response = requests.get(url, timeout=10, verify=False)
        
        # Show History
        if response.history:
            for i, resp in enumerate(response.history):
                print(Fore.WHITE + f"    {i+1}. {resp.url}  -->  ({resp.status_code})")
            print(Fore.GREEN + f"    [Final Destination]: {response.url}")
            return response.url, len(response.history)
        else:
            print(Fore.GREEN + f"    [✓] No Redirects. Direct Link.")
            return url, 0
            
    except Exception as e:
        print(Fore.RED + f"[-] URL Error: {e}")
        return None, 0

# --- STEP 2: SSL CERTIFICATE ANALYSIS ---
def analyze_ssl(url):
    print(Fore.YELLOW + "\n[+] Phase 2: Analyzing SSL Certificate...")
    
    parsed = urlparse(url)
    hostname = parsed.netloc
    
    context = ssl.create_default_context()
    
    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Extract Dates
                not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                
                # Calculate Age
                age = (datetime.datetime.now() - not_before).days
                issuer = dict(x[0] for x in cert['issuer'])
                common_name = issuer.get('commonName', 'Unknown')

                print(Fore.WHITE + f"    [Issuer]: {common_name}")
                print(Fore.WHITE + f"    [Valid From]: {not_before}")
                print(Fore.WHITE + f"    [Certificate Age]: {age} days")

                # Risk Logic
                if age < 14:
                    print(Fore.RED + "    [!!!] WARNING: Certificate is VERY NEW (< 14 days). High Phishing Risk!")
                    return "HIGH"
                elif "Let's Encrypt" in common_name and age < 30:
                    print(Fore.YELLOW + "    [!] CAUTION: Free SSL (Let's Encrypt) on a new site.")
                    return "MEDIUM"
                else:
                    print(Fore.GREEN + "    [✓] SSL Certificate looks established.")
                    return "LOW"

    except Exception as e:
        print(Fore.RED + f"    [-] SSL Scan Failed (Site might be HTTP only): {e}")
        return "CRITICAL (No SSL)"

# --- STEP 3: PORT SCANNING ---
def scan_ports(url):
    print(Fore.YELLOW + "\n[+] Phase 3: Scanning Suspicious Ports...")
    parsed = urlparse(url)
    hostname = parsed.netloc
    
    # Ports common in phishing hosting or hijacked servers
    ports = {
        21: "FTP",
        22: "SSH",
        80: "HTTP",
        443: "HTTPS",
        8080: "Alt-HTTP",
        3306: "MySQL"
    }
    
    open_ports = []
    
    for port, name in ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((hostname, port))
        if result == 0:
            print(Fore.RED + f"    [!] Open Port Found: {port} ({name})")
            open_ports.append(port)
        sock.close()
        
    if not open_ports:
        print(Fore.GREEN + "    [✓] No suspicious extra ports found.")

# --- MAIN LOGIC ---
def main():
    get_banner()
    target = input(Fore.GREEN + "Enter Suspicious URL: " + Style.RESET_ALL).strip()
    
    if not target.startswith("http"):
        target = "https://" + target
        
    # 1. Redirects
    final_url, redirect_count = analyze_redirects(target)
    
    if final_url:
        # 2. SSL Check (On Final URL)
        risk_level = analyze_ssl(final_url)
        
        # 3. Ports
        scan_ports(final_url)
        
        # 4. Final Verdict
        print(Fore.CYAN + "\n" + "="*40)
        print(Fore.CYAN + " FINAL VERDICT:")
        
        score = 0
        if redirect_count > 2: score += 30
        if risk_level == "HIGH": score += 50
        elif risk_level == "MEDIUM": score += 20
        elif risk_level == "CRITICAL (No SSL)": score += 80
        
        # URL Keyword Check
        if "@" in final_url or "-" in final_url: # Phishers often use hyphens (facebook-login.com)
            score += 20

        print(f"Phishing Risk Score: {score}/100")
        
        if score > 70:
            print(Fore.RED + "[!!!] DANGEROUS: This site is likely a PHISHING scam.")
        elif score > 40:
            print(Fore.YELLOW + "[!] SUSPICIOUS: Proceed with extreme caution.")
        else:
            print(Fore.GREEN + "[✓] SAFE: Site appears legitimate.")

if __name__ == "__main__":
    main()