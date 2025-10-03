#!/usr/bin/env python3
"""
OSINT Full Name Search - Flask Integrated Version
- Searches multiple search engines and social media platforms
- Returns structured results for dashboard and AI analysis
- Deduplication and relevance filtering
- Fast parallel processing
"""

import requests
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote_plus, unquote, urlparse
from bs4 import BeautifulSoup
import re
import os

# ---- Config ----
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Safari/605.1.15",
]
REQUESTS_TIMEOUT = 15

# Priority social media and professional platforms
PRIORITY_SITES = [
    "linkedin.com", "github.com", "twitter.com", "facebook.com", 
    "instagram.com", "youtube.com", "medium.com", "reddit.com",
    "pinterest.com", "tiktok.com", "twitch.tv", "spotify.com",
    "flickr.com", "vimeo.com", "dribbble.com", "behance.net",
    "researchgate.net", "academia.edu", "orcid.org", "keybase.io"
]

LEAK_SITES = {"pastebin.com", "paste.ee", "ghostbin.com", "gist.github.com", "scribd.com"}

# ---- Helpers ----
def get_headers():
    return {"User-Agent": USER_AGENTS[0]}

def clean_link(link: str) -> str:
    if not link:
        return link
    if link.startswith("//duckduckgo.com/l/?uddg="):
        link = link.replace("//duckduckgo.com/l/?uddg=", "")
        link = unquote(link)
    return link

def get_platform_from_url(url: str) -> str:
    try:
        domain = urlparse(url).netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        # Extract main domain for cleaner platform names
        parts = domain.split('.')
        if len(parts) >= 2:
            return parts[-2] + '.' + parts[-1]
        return domain
    except Exception:
        return "unknown"

def is_relevant_result(title: str, link: str, name: str) -> bool:
    """Check if result is relevant to the name search"""
    if not title or not link:
        return False
    
    name_lower = name.lower()
    text = (title + " " + link).lower()
    
    # Split name into parts for better matching
    name_parts = [part for part in name_lower.split() if len(part) > 2]
    
    # Require at least 2 name parts to match for better precision
    if len(name_parts) >= 2:
        matches = sum(1 for part in name_parts if part in text)
        return matches >= 2
    else:
        # For short names, require exact match
        return any(part in text for part in name_parts)

# ---- Search Engines ----
def search_duckduckgo(query: str, max_results: int = 20) -> list:
    """Search DuckDuckGo with improved result extraction"""
    try:
        results = []
        url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
        response = requests.get(url, headers=get_headers(), timeout=REQUESTS_TIMEOUT)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find result containers
        result_containers = soup.find_all('div', class_='result')
        
        for container in result_containers[:max_results]:
            try:
                title_elem = container.find('a', class_='result__a')
                if title_elem:
                    title = title_elem.get_text(strip=True)
                    link = clean_link(title_elem.get('href'))
                    
                    if link and link.startswith('http'):
                        platform = get_platform_from_url(link)
                        results.append({
                            "site": platform,
                            "title": title,
                            "url": link,
                            "found": True,
                            "type": "leak" if platform in LEAK_SITES else "profile"
                        })
            except Exception:
                continue
                
        return results
    except Exception as e:
        print(f"DuckDuckGo error: {e}")
        return []

def search_bing(query: str, max_results: int = 20) -> list:
    """Search Bing with improved parsing"""
    try:
        results = []
        url = f"https://www.bing.com/search?q={quote_plus(query)}"
        response = requests.get(url, headers=get_headers(), timeout=REQUESTS_TIMEOUT)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find organic results
        results = []
        for item in soup.find_all('li', class_='b_algo')[:max_results]:
            try:
                link_elem = item.find('a')
                if link_elem:
                    title = link_elem.get_text(strip=True)
                    link = link_elem.get('href')
                    
                    if link and link.startswith('http'):
                        platform = get_platform_from_url(link)
                        results.append({
                            "site": platform,
                            "title": title,
                            "url": link,
                            "found": True,
                            "type": "leak" if platform in LEAK_SITES else "profile"
                        })
            except Exception:
                continue
                
        return results
    except Exception as e:
        print(f"Bing error: {e}")
        return []

def search_social_media_direct(name: str) -> list:
    """Direct social media profile checks"""
    results = []
    
    # Common social media URL patterns
    social_patterns = [
        ("LinkedIn", f"https://www.linkedin.com/in/{quote_plus(name)}"),
        ("GitHub", f"https://github.com/{quote_plus(name.split()[0])}"),
        ("Twitter", f"https://twitter.com/{quote_plus(name.split()[0])}"),
        ("Instagram", f"https://instagram.com/{quote_plus(name.replace(' ', ''))}"),
        ("Facebook", f"https://facebook.com/{quote_plus(name.replace(' ', '.'))}"),
        ("YouTube", f"https://youtube.com/@{quote_plus(name.replace(' ', ''))}"),
    ]
    
    def check_social_media(site_name, url):
        try:
            response = requests.head(url, headers=get_headers(), timeout=10, allow_redirects=True)
            if response.status_code == 200:
                return {
                    "site": site_name,
                    "title": f"{name} - {site_name} Profile",
                    "url": url,
                    "found": True,
                    "type": "profile"
                }
        except Exception:
            pass
        return None
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for site_name, url in social_patterns:
            futures.append(executor.submit(check_social_media, site_name, url))
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
    
    return results

def search_people_search_engines(name: str) -> list:
    """Search people-specific search engines"""
    results = []
    
    people_engines = [
        ("PeekYou", f"https://peekyou.com/{quote_plus(name)}"),
        ("Spokeo", f"https://www.spokeo.com/{quote_plus(name)}"),
        ("ThatsThem", f"https://thatsthem.com/name/{quote_plus(name)}"),
        ("TruePeopleSearch", f"https://www.truepeoplesearch.com/results?name={quote_plus(name)}"),
    ]
    
    def check_people_engine(engine_name, url):
        try:
            response = requests.get(url, headers=get_headers(), timeout=10)
            if response.status_code == 200 and name.lower() in response.text.lower():
                return {
                    "site": engine_name,
                    "title": f"{name} - {engine_name} Record",
                    "url": url,
                    "found": True,
                    "type": "record"
                }
        except Exception:
            pass
        return None
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for engine_name, url in people_engines:
            futures.append(executor.submit(check_people_engine, engine_name, url))
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
    
    return results

# ---- Main Search Function ----
def run(name: str):
    """
    Main function to run full name OSINT search
    Returns structured results for Flask dashboard
    """
    if not name or len(name.strip().split()) < 2:
        return {
            "target": name,
            "status": "error",
            "sites": [],
            "error": "Please provide a full name (first and last name)"
        }
    
    print(f"[+] Starting OSINT search for: {name}")
    all_results = []
    
    try:
        # Run all search types in parallel
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(search_duckduckgo, name): "duckduckgo",
                executor.submit(search_bing, name): "bing", 
                executor.submit(search_social_media_direct, name): "social",
                executor.submit(search_people_search_engines, name): "people"
            }
            
            for future in as_completed(futures):
                try:
                    results = future.result()
                    all_results.extend(results)
                    print(f"[+] {futures[future]} found {len(results)} results")
                except Exception as e:
                    print(f"[-] Error in {futures[future]}: {e}")
        
        # Deduplicate results
        unique_results = []
        seen_urls = set()
        
        for result in all_results:
            url = result.get('url', '')
            if url and url not in seen_urls and is_relevant_result(result.get('title', ''), url, name):
                seen_urls.add(url)
                unique_results.append(result)
        
        # Sort by type and site
        unique_results.sort(key=lambda x: (x.get('type', ''), x.get('site', '')))
        
        # Format for dashboard compatibility
        formatted_results = []
        for result in unique_results[:50]:  # Limit to top 50 results
            formatted_results.append({
                "site": result.get("site", "unknown"),
                "url": result.get("url", ""),
                "found": result.get("found", True),
                "title": result.get("title", ""),
                "type": result.get("type", "profile")
            })
        
        print(f"[+] Search completed. Found {len(formatted_results)} relevant results")
        
        return {
            "target": name,
            "status": "completed",
            "sites": formatted_results,
            "summary": {
                "total_results": len(formatted_results),
                "profiles_found": len([r for r in formatted_results if r.get('type') == 'profile']),
                "leaks_found": len([r for r in formatted_results if r.get('type') == 'leak']),
                "records_found": len([r for r in formatted_results if r.get('type') == 'record'])
            }
        }
        
    except Exception as e:
        print(f"[-] Search failed: {e}")
        return {
            "target": name,
            "status": "error", 
            "sites": [],
            "error": f"Search failed: {str(e)}"
        }

# Test function
if __name__ == "__main__":
    test_name = "John Smith"
    print("Testing full name OSINT search...")
    results = run(test_name)
    print(f"Status: {results['status']}")
    print(f"Found {len(results['sites'])} results")
    for site in results['sites'][:5]:
        print(f"  {site['site']}: {site['url']}")
