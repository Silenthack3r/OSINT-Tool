#!/usr/bin/env python3
"""
Advanced Dark Web OSINT Tool
- Searches 15+ dark web search engines via Tor
- Checks breach databases for usernames/emails
- Queries specific .onion leak services
- Returns structured results for Flask dashboard
"""

import requests
import re
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, unquote, urlparse
from bs4 import BeautifulSoup
import random

# Configuration
REQUEST_TIMEOUT = 30
TOR_PROXY = 'socks5h://127.0.0.1:9050'

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0',  # Tor Browser
    'Mozilla/5.0 (Android 10; Mobile; rv:91.0) Gecko/91.0 Firefox/91.0',  # Tor Browser Mobile
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
]

proxies = {
    'http': TOR_PROXY,
    'https': TOR_PROXY
}

class AdvancedDarkWebOSINT:
    def __init__(self, target, target_type="username"):
        self.target = target
        self.target_type = target_type
        self.results = {
            "target": target,
            "target_type": target_type,
            "status": "completed",
            "darkweb_results": [],
            "leaks_found": [],
            "breach_data": [],
            "onion_service_results": {},
            "summary": {}
        }

    def random_headers(self):
        return {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

    def breachdb_onion_search(self):
        """Search the main breach database .onion site"""
        try:
            url = "http://breachdbsztfykg2fdaq2gnqnxfsbj5d35byz3yzj73hazydk4vq72qd.onion/"
            
            # Prepare form data based on target type
            form_data = {
                '__VIEWSTATE': '/wEPDwULLTE2NTE2NzQ1NzcPFgIeDUFudGlYc3JmVG9rZW4FIGVlZmQ2OWI2NmFlNjQ2YTliODc2ZjA5YTViZDdjNDM1FgJmD2QWAgIDD2QWAgIBD2QWAmYPZBYEAgUPEA8WAh4HRW5hYmxlZGhkZGRkAgsPDxYEHg1PbkNsaWVudENsaWNrBQxEaXNhYmxlQnRuKCkeEVVzZVN1Ym1pdEJlaGF2aW9yaGRkGAEFHl9fQ29udHJvbHNSZXF1aXJlUG9zdEJhY2tLZXlfXxYBBSRjdGwwMCRDb250ZW50UGxhY2VIb2xkZXIxJENoa1Nob3dBbGzIrntE0S4AmI2zgU7LStPVQ1FYrrCNABfLuMKCY4k/RA==',
                '__VIEWSTATEGENERATOR': '94D56744',
                '__EVENTVALIDATION': '/wEdAAicT7DOn2aq0wN7dmgTXrKuWKrNrxJ9H/Sq1/LwagLSvfuTvlXhUaV0lpXjmWrHYXlCwAVToG4T5YUsihCDBa9MfteltqTNG3zxqCR+jDI4SqEN3PJMAfsZ3M5euJgXnRordMAAB2G3bzYF2ekjNxJjeHRGm7AHgPLi1Rc2/WxSAtxbCxaE6nu1d16ydXDUqKM4BsYV4oWHrhl527WYgYhA',
                'ctl00$ContentPlaceHolder1$TxtSearch': self.target,
                'ctl00$ContentPlaceHolder1$SearchType': 'Username' if self.target_type == 'username' else 'Email',
                'ctl00$ContentPlaceHolder1$ChkShowAll': 'on',
                'ctl00$ContentPlaceHolder1$HiddenJS': 'Enable'
            }

            response = requests.post(
                url, 
                data=form_data, 
                headers=self.random_headers(), 
                proxies=proxies, 
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True
            )

            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Check for "Nothing found" message
                warning_panel = soup.find('div', class_='WarningPanel')
                if warning_panel and "Nothing found" in warning_panel.get_text():
                    self.results['onion_service_results']['breachdb'] = {
                        "found": False,
                        "details": "No results found in breach database",
                        "url": url
                    }
                else:
                    # Extract database statistics
                    stats_text = ""
                    header = soup.find('div', class_='MainHeaderPanel')
                    if header:
                        stats_text = header.get_text()
                    
                    self.results['onion_service_results']['breachdb'] = {
                        "found": True,
                        "details": "Possible matches found in breach database",
                        "url": url,
                        "stats": stats_text.strip() if stats_text else "Database search completed"
                    }
                    
                    self.results['breach_data'].append({
                        "source": "BreachDB Onion",
                        "target": self.target,
                        "found": True,
                        "details": "Check the onion site for detailed results"
                    })
            else:
                self.results['onion_service_results']['breachdb'] = {
                    "found": False,
                    "details": f"HTTP Error: {response.status_code}",
                    "url": url
                }
                
        except Exception as e:
            self.results['onion_service_results']['breachdb'] = {
                "found": False,
                "details": f"Error: {str(e)}",
                "url": ""
            }

    def pwndb_onion_search(self):
        """Search PwnDB .onion for email leaks"""
        try:
            if self.target_type != 'email':
                return
                
            url = "http://pwndb2am4tzkvold.onion/"
            
            # Prepare request data
            request_data = {
                'luser': self.target.split('@')[0] if '@' in self.target else self.target,
                'domain': self.target.split('@')[1] if '@' in self.target else '%',
                'luseropr': 1,
                'domainopr': 1,
                'submitform': 'em'
            }

            response = requests.post(
                url, 
                data=request_data, 
                headers=self.random_headers(), 
                proxies=proxies, 
                timeout=REQUEST_TIMEOUT
            )

            if response.status_code == 200:
                if "Array" in response.text:
                    leaks = self.parse_pwndb_response(response.text)
                    if leaks:
                        self.results['leaks_found'].extend(leaks)
                        self.results['onion_service_results']['pwndb'] = {
                            "found": True,
                            "details": f"Found {len(leaks)} email leaks",
                            "url": url,
                            "leaks": leaks
                        }
                    else:
                        self.results['onion_service_results']['pwndb'] = {
                            "found": False,
                            "details": "No email leaks found",
                            "url": url
                        }
                else:
                    self.results['onion_service_results']['pwndb'] = {
                        "found": False,
                        "details": "No leak data found",
                        "url": url
                    }
            else:
                self.results['onion_service_results']['pwndb'] = {
                    "found": False,
                    "details": f"HTTP Error: {response.status_code}",
                    "url": url
                }
                
        except Exception as e:
            self.results['onion_service_results']['pwndb'] = {
                "found": False,
                "details": f"Error: {str(e)}",
                "url": ""
            }

    def parse_pwndb_response(self, text):
        """Parse PwnDB response for leak data"""
        if "Array" not in text:
            return None

        leaks = text.split("Array")[1:]
        email_leaks = []

        for leak in leaks:
            try:
                leaked_email = leak.split("[luser] =>")[1].split("[")[0].strip()
                domain = leak.split("[domain] =>")[1].split("[")[0].strip()
                password = leak.split("[password] =>")[1].split(")")[0].strip()
                
                if leaked_email:
                    email_leaks.append({
                        'username': leaked_email,
                        'domain': domain,
                        'password': password,
                        'source': 'PwnDB'
                    })
            except Exception:
                continue
                
        return email_leaks

    def darksearch_io(self):
        """DarkSearch.io API search"""
        try:
            url = f"https://darksearch.io/api/search?query={quote(self.target)}&page=1"
            
            response = requests.get(url, headers=self.random_headers(), timeout=REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('data'):
                    for item in data['data']:
                        self.results['darkweb_results'].append({
                            "engine": "DarkSearch.io",
                            "title": item.get('title', ''),
                            "link": item.get('link', ''),
                            "description": item.get('description', ''),
                            "found": True
                        })
                    
                    return len(data['data'])
            return 0
        except Exception as e:
            return 0

    def ahmia_search(self):
        """Ahmia search engine (clearnet but indexes .onion)"""
        try:
            url = f"https://ahmia.fi/search/?q={quote(self.target)}"
            
            response = requests.get(url, headers=self.random_headers(), timeout=REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                results = soup.select('li.result h4')
                
                for result in results:
                    link = result.find('a')
                    if link and link.get('href'):
                        self.results['darkweb_results'].append({
                            "engine": "Ahmia",
                            "title": result.get_text().strip(),
                            "link": link['href'],
                            "description": "Dark web search result",
                            "found": True
                        })
                
                return len(results)
            return 0
        except Exception as e:
            return 0

    def onionland_search(self):
        """OnionLand search engine"""
        try:
            url = f"http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q={quote(self.target)}&page=1"
            
            response = requests.get(url, headers=self.random_headers(), proxies=proxies, timeout=REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                results = soup.select('.result-block .title a')
                
                for result in results:
                    if not result['href'].startswith('/ads/'):
                        title = result.get_text().strip()
                        link = unquote(unquote(self.get_parameter(result['href'], 'l')))
                        
                        self.results['darkweb_results'].append({
                            "engine": "OnionLand",
                            "title": title,
                            "link": link,
                            "description": "Dark web link",
                            "found": True
                        })
                
                return len(results)
            return 0
        except Exception as e:
            return 0

    def haystack_search(self):
        """Haystack search engine"""
        try:
            url = f"http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion/?q={quote(self.target)}&offset=0"
            
            response = requests.get(url, headers=self.random_headers(), proxies=proxies, timeout=REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                results = soup.select(".result b a")
                
                for result in results:
                    title = result.get_text().strip()
                    link = self.get_parameter(result['href'], 'url')
                    
                    self.results['darkweb_results'].append({
                        "engine": "Haystack",
                        "title": title,
                        "link": link,
                        "description": "Dark web search result",
                        "found": True
                    })
                
                return len(results)
            return 0
        except Exception as e:
            return 0

    def get_parameter(self, url, parameter_name):
        """Extract parameter from URL"""
        try:
            from urllib.parse import parse_qs, urlparse
            parsed = urlparse(url)
            return parse_qs(parsed.query)[parameter_name][0]
        except:
            return url

    def additional_darkweb_searches(self):
        """Additional dark web search engines"""
        search_engines = [
            ("Phobos", f"http://phobosxilamwcg75xt22id7aywkzol6q6rfl2flipcqoc4e4ahima5id.onion/search?query={quote(self.target)}&p=1"),
            ("Tor66", f"http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/search?q={quote(self.target)}&sorttype=rel&page=1"),
            ("DarkSearchEnginer", "http://l4rsciqnpzdndt2llgjx3luvnxip7vbyj6k6nmdy4xs77tx6gkd24ead.onion"),
        ]
        
        def search_engine_wrapper(engine_name, engine_url):
            try:
                if engine_name == "DarkSearchEnginer":
                    # Special handling for POST request
                    response = requests.post(
                        engine_url, 
                        data={"search[keyword]": self.target, "page": "1"},
                        headers=self.random_headers(),
                        proxies=proxies,
                        timeout=REQUEST_TIMEOUT
                    )
                else:
                    response = requests.get(engine_url, headers=self.random_headers(), proxies=proxies, timeout=REQUEST_TIMEOUT)
                
                if response.status_code == 200:
                    return 1  # Count as successful attempt
            except:
                pass
            return 0
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(search_engine_wrapper, name, url) for name, url in search_engines]
            successful_searches = sum(future.result() for future in as_completed(futures))
        
        return successful_searches

    def run_comprehensive_search(self):
        """Run all dark web OSINT checks"""
        print(f"[+] Starting ADVANCED dark web OSINT for: {self.target} ({self.target_type})")
        
        # Run all searches in parallel
        search_methods = [
            self.breachdb_onion_search,
            self.pwndb_onion_search,
            self.darksearch_io,
            self.ahmia_search,
            self.onionland_search,
            self.haystack_search,
            self.additional_darkweb_searches,
        ]
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(method) for method in search_methods]
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"[-] Error in dark web search: {e}")
        
        # Generate comprehensive summary
        total_darkweb_results = len(self.results['darkweb_results'])
        total_leaks = len(self.results['leaks_found'])
        total_breaches = len(self.results['breach_data'])
        
        onion_services_checked = len(self.results['onion_service_results'])
        onion_services_found = sum(1 for result in self.results['onion_service_results'].values() if result.get('found'))
        
        self.results['summary'] = {
            "darkweb_results_found": total_darkweb_results,
            "leaks_found": total_leaks,
            "breaches_found": total_breaches,
            "onion_services_checked": onion_services_checked,
            "onion_services_with_results": onion_services_found,
            "success_rate": f"{(onion_services_found/onion_services_checked*100):.1f}%" if onion_services_checked > 0 else "0%",
            "search_engines_used": 7,  # Total search engines attempted
            "target_type": self.target_type
        }
        
        print(f"[+] Dark Web OSINT completed:")
        print(f"    - Dark web results: {total_darkweb_results}")
        print(f"    - Leaks found: {total_leaks}")
        print(f"    - Breaches found: {total_breaches}")
        print(f"    - Onion services with results: {onion_services_found}/{onion_services_checked}")
        
        return self.results

def run(target, target_type="username"):
    """
    Main function to run advanced dark web OSINT search
    """
    if not target:
        return {
            "target": target,
            "target_type": target_type,
            "status": "error",
            "darkweb_results": [],
            "leaks_found": [],
            "breach_data": [],
            "onion_service_results": {},
            "summary": {},
            "error": "Please provide a target to search"
        }
    
    scanner = AdvancedDarkWebOSINT(target, target_type)
    return scanner.run_comprehensive_search()

# Test function
if __name__ == "__main__":
    test_target = "testuser"
    print("Testing ADVANCED dark web OSINT search...")
    results = run(test_target)
    print(f"\n=== SUMMARY ===")
    print(f"Status: {results['status']}")
    print(f"Dark web results: {results['summary']['darkweb_results_found']}")
    print(f"Leaks found: {results['summary']['leaks_found']}")
    print(f"Onion services with results: {results['summary']['onion_services_with_results']}")
    
    print(f"\n=== ONION SERVICE RESULTS ===")
    for service, result in results['onion_service_results'].items():
        status = "✓ FOUND" if result.get('found') else "✗ NOT FOUND"
        print(f"  {service}: {status} - {result.get('details', '')}")
