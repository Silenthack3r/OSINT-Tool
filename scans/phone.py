import requests
import json
import re
import time
import phonenumbers
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote_plus
from bs4 import BeautifulSoup

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

class AdvancedPhoneOSINT:
    def __init__(self, phone_number, country_code="+1"):
        self.country_code = country_code
        self.original_phone = phone_number
        self.phone = self.clean_and_format_phone(phone_number, country_code)
        self.international_phone = self.format_international()
        
        self.results = {
            "target": self.international_phone,
            "status": "completed", 
            "sites": [],
            "carrier_info": {},
            "location_info": {},
            "social_profiles": [],
            "breach_data": [],
            "technical_info": {},
            "threat_intel": [],
            "number_analysis": {}
        }

    def clean_and_format_phone(self, phone, country_code):
        """Clean phone number and apply country code formatting"""
        try:
            # Remove all non-digit characters
            cleaned = re.sub(r'\D', '', phone)
            
            # Remove leading zero if present (common in local formats)
            if cleaned.startswith('0'):
                cleaned = cleaned[1:]
            
            # Apply country code
            country_digits = country_code.replace('+', '')
            if not cleaned.startswith(country_digits):
                cleaned = country_digits + cleaned
                
            return cleaned
        except Exception as e:
            print(f"Error cleaning phone: {e}")
            return phone

    def format_international(self):
        """Format phone number in international format"""
        try:
            # Use phonenumbers library for proper formatting
            parsed = phonenumbers.parse(f"+{self.phone}", None)
            return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        except:
            return f"+{self.phone}"

    def truecaller_advanced(self):
        """Advanced Truecaller lookup"""
        try:
            url = f"https://www.truecaller.com/search/in/{quote_plus(self.international_phone.replace(' ', ''))}"
            response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract comprehensive information
                extracted_data = {}
                
                # Name extraction
                name_patterns = [
                    r'"name":"([^"]+)"',
                    r'<title>([^<]+)</title>',
                    r'profile-name[^>]*>([^<]+)<',
                    r'Truecaller.*?([A-Za-z\s]+)'
                ]
                
                for pattern in name_patterns:
                    matches = re.findall(pattern, response.text)
                    if matches and len(matches[0]) > 2:
                        extracted_data['name'] = matches[0]
                        break
                
                # Location extraction
                location_patterns = [
                    r'"location":"([^"]+)"',
                    r'location[^>]*>([^<]+)<',
                    r'address[^>]*>([^<]+)<'
                ]
                
                for pattern in location_patterns:
                    matches = re.findall(pattern, response.text)
                    if matches:
                        extracted_data['location'] = matches[0]
                        break
                
                # Spam score detection
                spam_indicators = ['spam', 'reported', 'fraud', 'scam']
                spam_score = sum(1 for indicator in spam_indicators if indicator in response.text.lower())
                
                if extracted_data:
                    details = []
                    if 'name' in extracted_data:
                        details.append(f"Name: {extracted_data['name']}")
                    if 'location' in extracted_data:
                        details.append(f"Location: {extracted_data['location']}")
                    if spam_score > 0:
                        details.append(f"Spam indicators: {spam_score}")
                    
                    self.results['sites'].append({
                        "site": "Truecaller",
                        "url": url,
                        "found": True,
                        "type": "reverse_lookup",
                        "details": " | ".join(details)
                    })
                    
                    # Update results
                    if 'name' in extracted_data:
                        self.results['number_analysis']['name'] = extracted_data['name']
                    if 'location' in extracted_data:
                        self.results['location_info']['truecaller'] = extracted_data['location']
                    if spam_score > 0:
                        self.results['threat_intel'].append(f"Truecaller spam indicators: {spam_score}")
                else:
                    self.results['sites'].append({
                        "site": "Truecaller", 
                        "url": url,
                        "found": False,
                        "type": "reverse_lookup",
                        "details": "No public information"
                    })
                    
        except Exception as e:
            self.results['sites'].append({
                "site": "Truecaller",
                "url": "",
                "found": False,
                "type": "reverse_lookup", 
                "details": f"Error: {str(e)}"
            })

    def numspy_search(self):
        """Numspy phone lookup"""
        try:
            url = f"https://numspy.io/{quote_plus(self.international_phone.replace(' ', ''))}"
            response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                if "not found" not in response.text.lower() and "error" not in response.text.lower():
                    # Extract information from Numspy
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    info_indicators = ['carrier', 'location', 'type', 'timezone']
                    found_info = []
                    
                    for indicator in info_indicators:
                        if indicator in response.text.lower():
                            found_info.append(indicator)
                    
                    self.results['sites'].append({
                        "site": "Numspy",
                        "url": url,
                        "found": True,
                        "type": "lookup",
                        "details": f"Data points: {', '.join(found_info)}" if found_info else "Information available"
                    })
                else:
                    self.results['sites'].append({
                        "site": "Numspy",
                        "url": url,
                        "found": False,
                        "type": "lookup", 
                        "details": "No information found"
                    })
                    
        except Exception as e:
            self.results['sites'].append({
                "site": "Numspy",
                "url": "",
                "found": False,
                "type": "lookup",
                "details": f"Error: {str(e)}"
            })

    def opencnam_lookup(self):
        """OpenCNAM caller ID lookup"""
        try:
            url = f"https://api.opencnam.com/v3/phone/{quote_plus(self.phone)}?format=json"
            response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('name') and data['name'] != 'Unknown':
                    self.results['sites'].append({
                        "site": "OpenCNAM",
                        "url": f"https://opencnam.com/phone/{self.phone}",
                        "found": True,
                        "type": "caller_id",
                        "details": f"Caller ID: {data.get('name')}"
                    })
                    
                    self.results['number_analysis']['opencnam_name'] = data.get('name')
                else:
                    self.results['sites'].append({
                        "site": "OpenCNAM",
                        "url": f"https://opencnam.com/phone/{self.phone}",
                        "found": False,
                        "type": "caller_id",
                        "details": "No caller ID information"
                    })
                    
        except Exception as e:
            self.results['sites'].append({
                "site": "OpenCNAM",
                "url": "",
                "found": False,
                "type": "caller_id",
                "details": f"Error: {str(e)}"
            })

    def freecarrierlookup_advanced(self):
        """Advanced carrier lookup"""
        try:
            url = f"https://freecarrierlookup.com/?phone={quote_plus(self.phone)}"
            response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                # Enhanced carrier information extraction
                carrier_patterns = [
                    r'Carrier[^>]*>([^<]+)<',
                    r'Provider[^>]*>([^<]+)<',
                    r'carrier[^>]*>([^<]+)<',
                    r'Service Provider[^>]*>([^<]+)<'
                ]
                
                carrier = None
                for pattern in carrier_patterns:
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    if matches:
                        carrier = matches[0].strip()
                        break
                
                if carrier:
                    self.results['sites'].append({
                        "site": "FreeCarrierLookup",
                        "url": url,
                        "found": True,
                        "type": "carrier",
                        "details": f"Carrier: {carrier}"
                    })
                    
                    self.results['carrier_info']['primary'] = carrier
                    self.results['technical_info']['carrier'] = carrier
                else:
                    self.results['sites'].append({
                        "site": "FreeCarrierLookup",
                        "url": url,
                        "found": False,
                        "type": "carrier",
                        "details": "No carrier information"
                    })
                    
        except Exception as e:
            self.results['sites'].append({
                "site": "FreeCarrierLookup",
                "url": "",
                "found": False,
                "type": "carrier",
                "details": f"Error: {str(e)}"
            })

    def phonevalidator_advanced(self):
        """Advanced phone validation"""
        try:
            url = f"https://www.phonevalidator.com/result?phone={quote_plus(self.phone)}"
            response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                # Comprehensive validation data extraction
                validation_data = {}
                
                validation_patterns = {
                    'valid': r'Valid[^>]*>([^<]+)<',
                    'carrier': r'Carrier[^>]*>([^<]+)<',
                    'location': r'Location[^>]*>([^<]+)<',
                    'line_type': r'Line Type[^>]*>([^<]+)<'
                }
                
                for key, pattern in validation_patterns.items():
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    if matches:
                        validation_data[key] = matches[0].strip()
                
                if validation_data:
                    details = [f"{k}: {v}" for k, v in validation_data.items()]
                    self.results['sites'].append({
                        "site": "PhoneValidator",
                        "url": url,
                        "found": True,
                        "type": "validation",
                        "details": " | ".join(details)
                    })
                    
                    # Update technical info
                    self.results['technical_info']['validation'] = validation_data
                else:
                    self.results['sites'].append({
                        "site": "PhoneValidator",
                        "url": url,
                        "found": False,
                        "type": "validation",
                        "details": "No validation data"
                    })
                    
        except Exception as e:
            self.results['sites'].append({
                "site": "PhoneValidator",
                "url": "",
                "found": False,
                "type": "validation",
                "details": f"Error: {str(e)}"
            })

    def social_media_deep_search(self):
        """Deep social media profile discovery"""
        social_platforms = [
            # Messaging apps
            ("Telegram", f"https://t.me/+{self.phone}", "messaging", True),
            ("WhatsApp", f"https://wa.me/{self.phone}", "messaging", True),
            ("Signal", f"https://signal.me/#p/+{self.phone}", "messaging", False),
            ("Viber", f"viber://add?number={self.phone}", "messaging", False),
            
            # Social networks
            ("Facebook", f"https://www.facebook.com/login/identify?ctx=recover&phone={quote_plus(self.international_phone)}", "social", True),
            ("Instagram", f"https://www.instagram.com/accounts/account_recovery/?phone={quote_plus(self.international_phone)}", "social", True),
            ("Twitter", f"https://twitter.com/search?q={quote_plus(self.international_phone)}&src=typed_query", "social", True),
            ("LinkedIn", f"https://www.linkedin.com/pub/dir/?phone={quote_plus(self.international_phone)}", "professional", True),
            
            # Additional platforms
            ("Snapchat", f"https://accounts.snapchat.com/accounts/v2/login", "social", False),
            ("Discord", f"https://discord.com/login", "social", False),
        ]
        
        def check_social_platform(platform_name, url, platform_type, do_http_check):
            try:
                if not do_http_check:
                    return {
                        "site": platform_name,
                        "url": url,
                        "found": True,
                        "type": platform_type,
                        "details": "App link available"
                    }
                
                response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
                if response.status_code == 200:
                    # Advanced pattern matching for account existence
                    positive_indicators = [
                        'account', 'profile', 'user', 'found', 'exists', 'recover',
                        'log in', 'sign in', 'phone number'
                    ]
                    
                    negative_indicators = [
                        'not found', 'no account', 'invalid', 'error'
                    ]
                    
                    text_lower = response.text.lower()
                    positive_score = sum(1 for ind in positive_indicators if ind in text_lower)
                    negative_score = sum(1 for ind in negative_indicators if ind in text_lower)
                    
                    if positive_score > negative_score:
                        return {
                            "site": platform_name,
                            "url": url,
                            "found": True,
                            "type": platform_type,
                            "details": f"Account association detected (score: {positive_score})"
                        }
            except Exception:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(check_social_platform, name, url, ptype, check) for name, url, ptype, check in social_platforms]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.results['sites'].append(result)
                    if result['type'] in ['social', 'messaging', 'professional']:
                        self.results['social_profiles'].append({
                            "platform": result['site'],
                            "url": result['url'],
                            "type": result['type']
                        })

    def breach_intelligence(self):
        """Advanced breach data intelligence"""
        breach_services = [
            ("HaveIBeenPwned", f"https://haveibeenpwned.com/unifiedsearch/{quote_plus(self.international_phone)}"),
            ("DeHashed", f"https://dehashed.com/search?query={quote_plus(self.international_phone)}"),
            ("Vigilante.pw", f"https://vigilante.pw/breached-phone/{quote_plus(self.international_phone)}"),
            ("LeakCheck", f"https://leakcheck.io/search?query={quote_plus(self.international_phone)}"),
            ("Snusbase", f"https://snusbase.com/search?term={quote_plus(self.international_phone)}"),
        ]
        
        def check_breach_service(service_name, url):
            try:
                response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
                if response.status_code == 200:
                    breach_indicators = [
                        'password', 'hash', 'breach', 'leak', 'compromised',
                        'database', 'exposed', 'found', 'results', 'pwned'
                    ]
                    
                    text_lower = response.text.lower()
                    found_indicators = [ind for ind in breach_indicators if ind in text_lower]
                    
                    if found_indicators and 'no results' not in text_lower and 'not found' not in text_lower:
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
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(check_breach_service, name, url) for name, url in breach_services]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.results['sites'].append(result)
                    self.results['breach_data'].append(result)

    def advanced_technical_analysis(self):
        """Comprehensive technical number analysis"""
        try:
            # Parse with phonenumbers for detailed analysis
            parsed = phonenumbers.parse(self.international_phone, None)
            
            analysis = {
                'international_format': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                'e164_format': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
                'national_format': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
                'country_code': parsed.country_code,
                'national_number': parsed.national_number,
                'is_valid': phonenumbers.is_valid_number(parsed),
                'is_possible': phonenumbers.is_possible_number(parsed),
                'number_type': str(phonenumbers.number_type(parsed)) if phonenumbers.is_valid_number(parsed) else 'Unknown',
                'region_code': phonenumbers.region_code_for_number(parsed) if phonenumbers.is_valid_number(parsed) else 'Unknown',
                'location': phonenumbers.geocoder.description_for_number(parsed, "en") if phonenumbers.is_valid_number(parsed) else 'Unknown',
                'timezones': phonenumbers.timezone.time_zones_for_number(parsed) if phonenumbers.is_valid_number(parsed) else []
            }
            
            self.results['number_analysis']['technical'] = analysis
            self.results['location_info']['phonenumbers'] = analysis.get('location', 'Unknown')
            
            # Threat analysis
            threats = []
            
            # VOIP detection
            if analysis.get('number_type') == 'VOIP':
                threats.append("VOIP number detected")
            
            # Premium rate detection
            premium_prefixes = ['900', '976']
            if any(self.phone.startswith(prefix) for prefix in premium_prefixes):
                threats.append("Premium rate number")
            
            # Toll-free detection
            toll_free_prefixes = ['800', '888', '877', '866', '855', '844']
            if any(self.phone.startswith(prefix) for prefix in toll_free_prefixes):
                threats.append("Toll-free number")
            
            if threats:
                self.results['threat_intel'].extend(threats)
                
        except Exception as e:
            print(f"Technical analysis error: {e}")

    def run_comprehensive_analysis(self):
        """Run all advanced phone OSINT checks"""
        print(f"[+] Starting ADVANCED phone OSINT for: {self.international_phone}")
        print(f"[+] Original input: {self.original_phone}, Country code: {self.country_code}")
        
        analysis_methods = [
            self.truecaller_advanced,
            self.numspy_search,
            self.opencnam_lookup,
            self.freecarrierlookup_advanced,
            self.phonevalidator_advanced,
            self.social_media_deep_search,
            self.breach_intelligence,
            self.advanced_technical_analysis,
        ]
        
        # Run all methods in parallel
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(method) for method in analysis_methods]
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"[-] Error in phone analysis: {e}")
        
        # Generate comprehensive summary
        total_checks = len(self.results['sites'])
        successful_checks = len([s for s in self.results['sites'] if s['found']])
        social_count = len(self.results['social_profiles'])
        breach_count = len(self.results['breach_data'])
        
        self.results['summary'] = {
            "total_services_checked": total_checks,
            "successful_finds": successful_checks,
            "social_profiles": social_count,
            "breach_findings": breach_count,
            "carrier_info_found": bool(self.results['carrier_info']),
            "location_info_found": bool(self.results['location_info']),
            "name_identified": 'name' in self.results['number_analysis'],
            "success_rate": f"{(successful_checks/total_checks*100):.1f}%" if total_checks > 0 else "0%",
            "threat_indicators": len(self.results['threat_intel']),
            "formatted_number": self.international_phone
        }
        
        print(f"[+] ADVANCED Phone OSINT completed:")
        print(f"    - Services: {successful_checks}/{total_checks} successful")
        print(f"    - Social: {social_count} profiles") 
        print(f"    - Breaches: {breach_count} findings")
        print(f"    - Name identified: {self.results['summary']['name_identified']}")
        print(f"    - Threat Intel: {len(self.results['threat_intel'])} indicators")
        
        return self.results

def run(phone_number, country_code="+1"):
    """
    Main function to run advanced phone OSINT search
    """
    if not phone_number or len(phone_number) < 7:
        return {
            "target": phone_number,
            "status": "error",
            "sites": [],
            "carrier_info": {},
            "location_info": {},
            "social_profiles": [],
            "breach_data": [],
            "technical_info": {},
            "threat_intel": [],
            "number_analysis": {},
            "error": "Please provide a valid phone number"
        }
    
    scanner = AdvancedPhoneOSINT(phone_number, country_code)
    return scanner.run_comprehensive_analysis()

# Test function
if __name__ == "__main__":
    test_phone = "912312122"
    test_country = "+251"
    print("Testing ADVANCED phone OSINT search...")
    results = run(test_phone, test_country)
    print(f"\n=== SUMMARY ===")
    print(f"Status: {results['status']}")
    print(f"Formatted: {results['summary']['formatted_number']}")
    print(f"Successful finds: {results['summary']['successful_finds']}/{results['summary']['total_services_checked']}")
    print(f"Social profiles: {results['summary']['social_profiles']}")
    print(f"Breach findings: {results['summary']['breach_findings']}")
    
    print(f"\n=== TOP FINDINGS ===")
    for site in results['sites'][:10]:
        if site['found']:
            print(f"  ✓ {site['site']}: {site['details']}")