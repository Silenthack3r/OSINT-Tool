import requests
import re
import phonenumbers
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote_plus

# Configuration
REQUEST_TIMEOUT = 8
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
}

class SimplePhoneOSINT:
    def __init__(self, phone_number, country_code="+1"):
        self.phone = self.clean_phone(phone_number, country_code)
        self.country_code = country_code
        
        self.results = {
            "target": self.phone,
            "status": "completed", 
            "sites": [],
            "carrier_info": {},
            "location_info": {},
            "social_profiles": [],
            "technical_info": {},
            "summary": {}
        }

    def clean_phone(self, phone, country_code):
        """Simple phone cleaning"""
        # Remove all non-digit characters
        cleaned = re.sub(r'\D', '', str(phone))
        country_digits = str(country_code).replace('+', '')
        
        # Add country code if not present
        if not cleaned.startswith(country_digits):
            cleaned = country_digits + cleaned
            
        return cleaned

    def basic_phone_analysis(self):
        """Basic phone number analysis using phonenumbers library"""
        try:
            formatted_number = f"+{self.phone}"
            parsed = phonenumbers.parse(formatted_number, None)
            
            # Basic validation
            is_valid = phonenumbers.is_valid_number(parsed)
            number_type = phonenumbers.number_type(parsed) if is_valid else "UNKNOWN"
            location = phonenumbers.geocoder.description_for_number(parsed, "en") if is_valid else "Unknown"
            
            self.results['technical_info'] = {
                'is_valid': is_valid,
                'number_type': str(number_type),
                'location': location,
                'international_format': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                'country_code': parsed.country_code
            }
            
            self.results['sites'].append({
                "site": "Phone Number Analysis",
                "url": "",
                "found": True,
                "type": "technical",
                "details": f"Valid: {is_valid}, Type: {number_type}, Location: {location}"
            })
            
        except Exception as e:
            self.results['sites'].append({
                "site": "Phone Number Analysis",
                "url": "",
                "found": False,
                "type": "technical", 
                "details": f"Error: {str(e)}"
            })

    def check_social_media(self):
        """Check basic social media platforms"""
        social_platforms = [
            ("WhatsApp", f"https://wa.me/{self.phone}", "messaging"),
            ("Telegram", f"https://t.me/{self.phone}", "messaging"),
        ]
        
        def check_platform(name, url, ptype):
            try:
                response = requests.head(url, headers=HEADERS, timeout=5, allow_redirects=True)
                if response.status_code in [200, 301, 302]:
                    return {
                        "site": name,
                        "url": url,
                        "found": True,
                        "type": ptype,
                        "details": "Profile may exist"
                    }
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(check_platform, name, url, ptype) for name, url, ptype in social_platforms]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.results['sites'].append(result)
                    self.results['social_profiles'].append({
                        "platform": result['site'],
                        "url": result['url'],
                        "type": result['type']
                    })

    def check_carrier_info(self):
        """Simple carrier lookup"""
        try:
            # Use a simple API or lookup
            url = f"https://freecarrierlookup.com/?phone={self.phone}"
            response = requests.get(url, headers=HEADERS, timeout=10)
            
            if response.status_code == 200:
                # Simple check for carrier info
                if 'carrier' in response.text.lower() or 'operator' in response.text.lower():
                    self.results['sites'].append({
                        "site": "FreeCarrierLookup",
                        "url": url,
                        "found": True,
                        "type": "carrier",
                        "details": "Carrier information available"
                    })
                    self.results['carrier_info'] = {'source': 'FreeCarrierLookup'}
                else:
                    self.results['sites'].append({
                        "site": "FreeCarrierLookup",
                        "url": url,
                        "found": False,
                        "type": "carrier",
                        "details": "No carrier information found"
                    })
        except Exception as e:
            self.results['sites'].append({
                "site": "FreeCarrierLookup",
                "url": "",
                "found": False,
                "type": "carrier",
                "details": f"Error: {str(e)}"
            })

    def run_scan(self):
        """Run all phone OSINT checks"""
        print(f"[+] Starting phone OSINT for: {self.phone}")
        
        methods = [
            self.basic_phone_analysis,
            self.check_social_media,
            self.check_carrier_info,
        ]
        
        # Run methods sequentially to avoid overwhelming
        for method in methods:
            try:
                method()
            except Exception as e:
                print(f"[-] Error in {method.__name__}: {e}")
        
        # Generate summary
        total_checks = len(self.results['sites'])
        successful_checks = len([s for s in self.results['sites'] if s['found']])
        
        self.results['summary'] = {
            "total_services_checked": total_checks,
            "successful_finds": successful_checks,
            "social_profiles": len(self.results['social_profiles']),
            "carrier_info_found": bool(self.results['carrier_info']),
            "location_info_found": bool(self.results['location_info']),
            "formatted_number": self.results['technical_info'].get('international_format', f"+{self.phone}")
        }
        
        print(f"[+] Phone OSINT completed: {successful_checks}/{total_checks} successful")
        return self.results

def run(phone_number, country_code="+1"):
    """
    Main function to run phone OSINT search
    """
    if not phone_number or len(str(phone_number).strip()) < 7:
        return {
            "target": phone_number,
            "status": "error",
            "sites": [],
            "carrier_info": {},
            "location_info": {},
            "social_profiles": [],
            "technical_info": {},
            "error": "Please provide a valid phone number (at least 7 digits)"
        }
    
    scanner = SimplePhoneOSINT(phone_number, country_code)
    return scanner.run_scan()

# Test
if __name__ == "__main__":
    results = run("912312122", "+251")
    print(f"Status: {results['status']}")
    print(f"Results: {len(results['sites'])} sites found")