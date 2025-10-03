import requests
import json
import re
import time
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote_plus, urlparse
from bs4 import BeautifulSoup
import socket
import whois
import ssl
import datetime
import hashlib

# Configuration
REQUEST_TIMEOUT = 20
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

headers = {
    'User-Agent': USER_AGENT,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
}

class AdvancedEmailOSINT:
    def __init__(self, email):
        self.email = email
        self.domain = email.split('@')[-1] if '@' in email else ''
        self.results = {
            "target": email,
            "status": "completed",
            "sites": [],
            "breaches": [],
            "social_profiles": [],
            "technical_info": {},
            "domain_info": {},
            "leaked_data": [],
            "threat_intel": [],
            "reputation_data": []
        }

    def advanced_hudson_rock(self):
        """Advanced Hudson Rock analysis with detailed computer extraction"""
        try:
            url = f"https://www.hudsonrock.com/api/json/v2/search/email/{quote_plus(self.email)}"
            response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('success') and data.get('data'):
                    computers = data['data'].get('computers', [])
                    leaks = data['data'].get('leaks', [])
                    
                    computer_details = []
                    for computer in computers:
                        comp_info = {
                            'hostname': computer.get('hostname'),
                            'ip': computer.get('ip'),
                            'os': computer.get('os'),
                            'country': computer.get('country'),
                            'first_seen': computer.get('first_seen'),
                            'last_seen': computer.get('last_seen')
                        }
                        computer_details.append(comp_info)
                    
                    leak_details = []
                    for leak in leaks:
                        leak_info = {
                            'type': leak.get('type'),
                            'count': leak.get('count'),
                            'source': leak.get('source')
                        }
                        leak_details.append(leak_info)
                    
                    self.results['technical_info']['hudson_rock'] = {
                        'computers': computer_details,
                        'leaks': leak_details,
                        'total_computers': len(computers),
                        'total_leaks': len(leaks)
                    }
                    
                    self.results['sites'].append({
                        "site": "Hudson Rock",
                        "url": f"https://www.hudsonrock.com/search/email/{self.email}",
                        "found": len(computers) > 0,
                        "type": "compromise_data",
                        "details": f"{len(computers)} computers, {len(leaks)} leak types"
                    })
                    
                    # Add to threat intelligence
                    if computers:
                        self.results['threat_intel'].extend([
                            f"Compromised computer: {comp.get('hostname', 'Unknown')} in {comp.get('country', 'Unknown')}"
                            for comp in computers
                        ])
                        
            else:
                # Fallback to HTML parsing
                url = f"https://www.hudsonrock.com/search/email/{quote_plus(self.email)}"
                response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Advanced pattern matching for computer data
                    patterns = {
                        'computer_names': r'[A-Za-z0-9\-_]+PC|[A-Za-z0-9\-_]+LAPTOP|[A-Za-z0-9\-_]+DESKTOP',
                        'ip_addresses': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                        'countries': r'Country:\s*([A-Za-z\s]+)',
                    }
                    
                    extracted_data = {}
                    for key, pattern in patterns.items():
                        matches = re.findall(pattern, response.text, re.IGNORECASE)
                        extracted_data[key] = list(set(matches))
                    
                    if any(extracted_data.values()):
                        self.results['sites'].append({
                            "site": "Hudson Rock",
                            "url": url,
                            "found": True,
                            "type": "compromise_data",
                            "details": f"Found: {', '.join([f'{k}: {len(v)}' for k, v in extracted_data.items() if v])}"
                        })
                        
        except Exception as e:
            self.results['sites'].append({
                "site": "Hudson Rock",
                "url": "",
                "found": False,
                "type": "compromise_data",
                "details": f"Error: {str(e)}"
            })

    def breach_directory_search(self):
        """Search multiple breach databases"""
        breach_services = [
            ("BreachDirectory", f"https://breachdirectory.org/index.php?email={quote_plus(self.email)}"),
            ("Vigilante.pw", f"https://vigilante.pw/breached-email/{quote_plus(self.email)}"),
            ("LeakCheck", f"https://leakcheck.io/search?query={quote_plus(self.email)}"),
            ("Snusbase", f"https://snusbase.com/search?term={quote_plus(self.email)}"),
        ]
        
        def check_breach_service(service_name, url):
            try:
                response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
                if response.status_code == 200:
                    indicators = [
                        'password', 'hash', 'breach', 'leak', 'compromised',
                        'database', 'exposed', 'found', 'results'
                    ]
                    
                    text_lower = response.text.lower()
                    found_indicators = [ind for ind in indicators if ind in text_lower]
                    
                    if found_indicators and 'no results' not in text_lower:
                        return {
                            "site": service_name,
                            "url": url,
                            "found": True,
                            "type": "breach",
                            "details": f"Breach indicators: {', '.join(found_indicators[:3])}"
                        }
            except Exception:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(check_breach_service, name, url) for name, url in breach_services]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.results['sites'].append(result)

    def social_intelligence_search(self):
        """Advanced social media and platform discovery"""
        social_patterns = [
            # Platform-specific patterns
            ("Facebook", f"https://www.facebook.com/{quote_plus(self.email)}", "social"),
            ("LinkedIn", f"https://www.linkedin.com/in/{quote_plus(self.email.split('@')[0])}", "professional"),
            ("Twitter", f"https://twitter.com/{quote_plus(self.email.split('@')[0])}", "social"),
            ("Instagram", f"https://instagram.com/{quote_plus(self.email.split('@')[0])}", "social"),
            ("GitHub", f"https://github.com/{quote_plus(self.email.split('@')[0])}", "technical"),
            ("GitLab", f"https://gitlab.com/{quote_plus(self.email.split('@')[0])}", "technical"),
            ("Reddit", f"https://reddit.com/user/{quote_plus(self.email.split('@')[0])}", "social"),
            ("Pinterest", f"https://pinterest.com/{quote_plus(self.email.split('@')[0])}", "social"),
            ("TikTok", f"https://tiktok.com/@{quote_plus(self.email.split('@')[0])}", "social"),
            ("Twitch", f"https://twitch.tv/{quote_plus(self.email.split('@')[0])}", "entertainment"),
            ("Spotify", f"https://open.spotify.com/user/{quote_plus(self.email.split('@')[0])}", "entertainment"),
            ("YouTube", f"https://youtube.com/@{quote_plus(self.email.split('@')[0])}", "entertainment"),
            ("Medium", f"https://medium.com/@{quote_plus(self.email.split('@')[0])}", "blogging"),
            ("Keybase", f"https://keybase.io/{quote_plus(self.email.split('@')[0])}", "crypto"),
        ]
        
        def check_social_platform(platform_name, url, platform_type):
            try:
                response = requests.head(url, headers=headers, timeout=10, allow_redirects=True)
                if response.status_code in [200, 301, 302]:
                    return {
                        "site": platform_name,
                        "url": url,
                        "found": True,
                        "type": platform_type,
                        "details": "Profile may exist"
                    }
            except Exception:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(check_social_platform, name, url, ptype) for name, url, ptype in social_patterns]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.results['sites'].append(result)
                    self.results['social_profiles'].append(result)

    def advanced_domain_analysis(self):
        """Comprehensive domain technical analysis"""
        if not self.domain:
            return
            
        try:
            # WHOIS information
            domain_info = whois.whois(self.domain)
            self.results['domain_info']['whois'] = {
                'registrar': domain_info.registrar,
                'creation_date': str(domain_info.creation_date),
                'expiration_date': str(domain_info.expiration_date),
                'name_servers': domain_info.name_servers,
                'emails': domain_info.emails,
            }
            
            # DNS records
            dns_records = {}
            record_types = ['A', 'MX', 'NS', 'TXT', 'CNAME']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(self.domain, record_type)
                    dns_records[record_type] = [str(rdata) for rdata in answers]
                except Exception:
                    dns_records[record_type] = []
            
            self.results['domain_info']['dns'] = dns_records
            
            # SSL certificate info
            try:
                context = ssl.create_default_context()
                with socket.create_connection((self.domain, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                        cert = ssock.getpeercert()
                        self.results['domain_info']['ssl'] = {
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'subject': dict(x[0] for x in cert['subject']),
                            'expires': cert['notAfter'],
                            'issued': cert['notBefore']
                        }
            except Exception:
                pass
            
            self.results['sites'].append({
                "site": "Domain Analysis",
                "url": f"https://whois.domaintools.com/{self.domain}",
                "found": True,
                "type": "technical",
                "details": f"WHOIS, DNS, SSL analysis completed"
            })
            
        except Exception as e:
            self.results['sites'].append({
                "site": "Domain Analysis",
                "url": "",
                "found": False,
                "type": "technical",
                "details": f"Error: {str(e)}"
            })

    def intelligence_search_engines(self):
        """Search intelligence and data breach platforms"""
        intel_services = [
            ("IntelligenceX", f"https://intelx.io/?s={quote_plus(self.email)}"),
            ("Epieos", f"https://epieos.com/?q={quote_plus(self.email)}"),
            ("Skymem", f"https://www.skymem.info/srch?q={quote_plus(self.email)}"),
            ("ThatsThem", f"https://thatsthem.com/email/{quote_plus(self.email)}"),
            ("SpyTox", f"https://www.spytox.com/email-lookup/{quote_plus(self.email)}"),
            ("TruePeopleSearch", f"https://www.truepeoplesearch.com/results?email={quote_plus(self.email)}"),
            ("Webmii", f"https://webmii.com/people?n={quote_plus(self.email)}"),
            ("NameAPI", f"https://www.nameapi.org/en/contact-data/email/{quote_plus(self.email)}"),
        ]
        
        def check_intel_service(service_name, url):
            try:
                response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
                if response.status_code == 200:
                    # Advanced content analysis
                    soup = BeautifulSoup(response.text, 'html.parser')
                    text = soup.get_text().lower()
                    
                    # Look for positive indicators
                    positive_indicators = [
                        'found', 'match', 'result', 'profile', 'contact',
                        'information', 'data', 'record', 'exists'
                    ]
                    
                    # Look for negative indicators
                    negative_indicators = [
                        'not found', 'no results', 'no match', 'no data',
                        'nothing found', '0 results'
                    ]
                    
                    positive_count = sum(1 for ind in positive_indicators if ind in text)
                    negative_count = sum(1 for ind in negative_indicators if ind in text)
                    
                    if positive_count > negative_count:
                        return {
                            "site": service_name,
                            "url": url,
                            "found": True,
                            "type": "intelligence",
                            "details": f"Positive indicators found ({positive_count})"
                        }
            except Exception:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(check_intel_service, name, url) for name, url in intel_services]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.results['sites'].append(result)

    def email_format_analysis(self):
        """Analyze email format patterns and common associations"""
        try:
            local_part = self.email.split('@')[0]
            
            # Common email format patterns
            formats_detected = []
            if '.' in local_part:
                formats_detected.append("first.last format")
            if '_' in local_part:
                formats_detected.append("first_last format")
            if local_part.isalpha():
                formats_detected.append("name only format")
            if any(char.isdigit() for char in local_part):
                formats_detected.append("contains numbers")
            
            # Guess possible full name
            if '.' in local_part:
                name_parts = local_part.split('.')
                if len(name_parts) == 2:
                    possible_name = f"{name_parts[0].title()} {name_parts[1].title()}"
                    self.results['technical_info']['inferred_name'] = possible_name
            
            self.results['technical_info']['email_format'] = {
                'local_part': local_part,
                'formats_detected': formats_detected,
                'length': len(local_part),
                'has_numbers': any(char.isdigit() for char in local_part),
                'has_special_chars': any(not char.isalnum() for char in local_part)
            }
            
        except Exception as e:
            pass

    def reputation_analysis(self):
        """Email reputation and risk assessment"""
        try:
            risk_factors = []
            
            # Disposable email check
            disposable_domains = ['tempmail.com', 'mailinator.com', 'guerrillamail.com', '10minutemail.com']
            if any(disp in self.domain for disp in disposable_domains):
                risk_factors.append("Disposable email domain")
            
            # Domain age assessment (if we have WHOIS data)
            if 'whois' in self.results['domain_info']:
                creation_date = self.results['domain_info']['whois'].get('creation_date', '')
                if creation_date:
                    try:
                        # Parse creation date and check if recent
                        if '2024' in creation_date or '2023' in creation_date:
                            risk_factors.append("Recently registered domain")
                    except:
                        pass
            
            # MX record check
            if 'dns' in self.results['domain_info']:
                mx_records = self.results['domain_info']['dns'].get('MX', [])
                if not mx_records:
                    risk_factors.append("No MX records found")
            
            # Add reputation data
            self.results['reputation_data'] = {
                'risk_factors': risk_factors,
                'risk_level': 'High' if risk_factors else 'Low',
                'disposable_domain': any(disp in self.domain for disp in disposable_domains)
            }
            
        except Exception as e:
            pass

    def run_comprehensive_analysis(self):
        """Run all advanced email OSINT checks"""
        print(f"[+] Starting ADVANCED email OSINT for: {self.email}")
        
        analysis_methods = [
            self.advanced_hudson_rock,      # Detailed compromise data
            self.breach_directory_search,   # Multiple breach databases
            self.social_intelligence_search, # Social media discovery
            self.advanced_domain_analysis,  # Technical domain analysis
            self.intelligence_search_engines, # Intelligence platforms
            self.email_format_analysis,     # Email pattern analysis
            self.reputation_analysis,       # Risk assessment
        ]
        
        # Run all methods in parallel for maximum speed
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = [executor.submit(method) for method in analysis_methods]
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"[-] Error in analysis method: {e}")
        
        # Generate comprehensive summary
        total_checks = len(self.results['sites'])
        successful_checks = len([s for s in self.results['sites'] if s['found']])
        breach_count = len([s for s in self.results['sites'] if s['type'] == 'breach' and s['found']])
        social_count = len(self.results['social_profiles'])
        
        self.results['summary'] = {
            "total_services_checked": total_checks,
            "successful_finds": successful_checks,
            "breach_findings": breach_count,
            "social_profiles": social_count,
            "computers_compromised": len(self.results['technical_info'].get('hudson_rock', {}).get('computers', [])),
            "success_rate": f"{(successful_checks/total_checks*100):.1f}%" if total_checks > 0 else "0%",
            "risk_assessment": self.results['reputation_data'].get('risk_level', 'Unknown'),
            "domain_analyzed": bool(self.results['domain_info'])
        }
        
        print(f"[+] ADVANCED Email OSINT completed:")
        print(f"    - Services: {successful_checks}/{total_checks} successful")
        print(f"    - Breaches: {breach_count} found")
        print(f"    - Social: {social_count} profiles")
        print(f"    - Risk: {self.results['reputation_data'].get('risk_level', 'Unknown')}")
        
        return self.results

def run(email):
    """
    Main function to run advanced email OSINT search
    """
    if not email or '@' not in email:
        return {
            "target": email,
            "status": "error",
            "sites": [],
            "breaches": [],
            "social_profiles": [],
            "technical_info": {},
            "domain_info": {},
            "leaked_data": [],
            "threat_intel": [],
            "reputation_data": [],
            "error": "Please provide a valid email address"
        }
    
    scanner = AdvancedEmailOSINT(email)
    return scanner.run_comprehensive_analysis()

# Test function
if __name__ == "__main__":
    test_email = "test@example.com"
    print("Testing ADVANCED email OSINT search...")
    results = run(test_email)
    print(f"\n=== SUMMARY ===")
    print(f"Status: {results['status']}")
    print(f"Successful finds: {results['summary']['successful_finds']}/{results['summary']['total_services_checked']}")
    print(f"Breach findings: {results['summary']['breach_findings']}")
    print(f"Social profiles: {results['summary']['social_profiles']}")
    print(f"Risk level: {results['summary']['risk_assessment']}")
    
    print(f"\n=== TOP FINDINGS ===")
    for site in results['sites'][:10]:
        if site['found']:
            print(f"  ✓ {site['site']}: {site['details']}")