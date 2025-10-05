import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import re
from urllib.parse import urlparse
from uuid import uuid4
import difflib

# Get the directory where this script is located
current_dir = os.path.dirname(os.path.abspath(__file__))
users_json_path = os.path.join(current_dir, "users.json")

# Load users.json once
try:
    with open(users_json_path, "r", encoding="utf-8") as f:
        DATA = json.load(f)
except FileNotFoundError:
    print(f"Warning: users.json not found at {users_json_path}")
    DATA = {}
except json.JSONDecodeError:
    print("Warning: users.json contains invalid JSON")
    DATA = {}

# Create a session with connection pooling
SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
})

# Username mutations for common variations
MUTATIONS = {
    "a": ["@", "4"],
    "e": ["3"],
    "i": ["1", "!"],
    "o": ["0"],
    "s": ["$", "5"],
    "l": ["1"],
    "t": ["7"]
}

def mutate_username(username):
    """Generate simple mutated usernames for checking."""
    variants = [username]
    for i, char in enumerate(username.lower()):
        if char in MUTATIONS:
            for m in MUTATIONS[char]:
                variants.append(username[:i] + m + username[i+1:])
    return list(set(variants))  # Remove duplicates

def check_username_regex(username, regex_pattern):
    """Check if username matches the site's regex requirement."""
    if not regex_pattern:
        return True
    try:
        return bool(re.match(regex_pattern, username))
    except re.error:
        return True  # If regex is invalid, allow the check

def check_site(username, sitename, info):
    """Optimized site checker with faster validation."""
    # Fast regex check first
    regex_pattern = info.get("regexCheck")
    if not check_username_regex(username, regex_pattern):
        return {"site": sitename, "url": info["url"].format(username), "found": False, "reason": "regex_fail"}

    # Build URLs to try
    urls_to_try = [(info["url"].format(username), username)]
    
    # Only add mutations if no regex restriction (mutations rarely help and slow things down)
    if not regex_pattern and len(username) < 15:  # Only for reasonable length usernames
        for variant in mutate_username(username)[:3]:  # Limit to 3 mutations max
            urls_to_try.append((info["url"].format(variant), variant))

    for url, probe_username in urls_to_try:
        try:
            # --- FAST REQUEST PHASE ---
            timeout = (4, 6)  # (connect_timeout, read_timeout) - much faster
            
            if info.get("request_method") == "POST":
                if "request_payload" in info:
                    payload = info["request_payload"]
                    payload_str = json.dumps(payload)
                    if "{username}" in payload_str:
                        payload_str = payload_str.replace("{username}", probe_username)
                    else:
                        payload_str = payload_str.replace("{}", probe_username)
                    payload = json.loads(payload_str)
                    response = SESSION.post(
                        info.get("urlProbe", url),
                        json=payload,
                        timeout=timeout,
                        allow_redirects=True
                    )
                else:
                    continue
            else:
                # Normal GET request with session (connection reuse)
                response = SESSION.get(url, timeout=timeout, allow_redirects=True)

            # --- FAST VALIDATION PHASE ---
            resp_code = response.status_code
            resp_text = response.text or ""
            resp_len = len(resp_text)

            # Quick status code check - fastest filter
            if resp_code == 404:
                continue  # Definitely not found
            
            if resp_code != 200:
                if resp_code >= 400:  # Client errors
                    continue
                # For redirects, do a quick URL check
                final_url = response.url.lower()
                if any(path in final_url for path in ["/login", "/signin", "/signup", "/register"]):
                    continue

            # Skip very small responses (likely error pages)
            if resp_len < 200:
                continue

            # --- SMART CONTENT CHECK (OPTIMIZED) ---
            # Only check a small portion of the page for speed
            sample_size = min(5000, resp_len)
            snippet = resp_text[:sample_size].lower()

            # Fast error message detection
            error_msgs = info.get("errorMsg", [])
            if isinstance(error_msgs, str):
                error_msgs = [error_msgs]
            
            # Quick string search instead of complex logic
            if any(msg.lower() in snippet for msg in error_msgs if msg):
                continue

            # Common 404 patterns
            COMMON_404 = ["user not found", "page not found", "no such user", "doesn't exist", "not exist", "404"]
            if any(msg in snippet for msg in COMMON_404):
                continue

            # If we passed all checks, consider it found
            return {
                "site": sitename,
                "url": url,
                "found": True,
                "urlMain": info.get("urlMain", ""),
                "isNSFW": info.get("isNSFW", False)
            }

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, 
                requests.exceptions.RequestException, Exception):
            continue  # Try next mutation or skip

    return {
        "site": sitename, 
        "url": info["url"].format(username), 
        "found": False,
        "urlMain": info.get("urlMain", ""),
        "isNSFW": info.get("isNSFW", False)
    }

def run(username):
    """Run all site checks in parallel with optimized settings."""
    if not DATA:
        return {
            "target": username, 
            "status": "error", 
            "sites": [],
            "error": "users.json not loaded properly"
        }
    
    results = []
    try:
        # INCREASED THREAD COUNT + connection pooling = much faster
        with ThreadPoolExecutor(max_workers=40) as executor:  # Increased from 15 to 40
            futures = []
            for sitename, info in DATA.items():
                if "url" not in info:
                    continue
                futures.append(executor.submit(check_site, username, sitename, info))

            completed = 0
            total = len(futures)
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                    completed += 1
                    
                    # Progress every 20 sites
                    if completed % 20 == 0:
                        print(f"Progress: {completed}/{total} sites checked")
                        
                except Exception as e:
                    print(f"Error processing site: {e}")
                    continue

        # Sort results
        found_sites = [r for r in results if r["found"]]
        not_found_sites = [r for r in results if not r["found"]]
        
        found_sites.sort(key=lambda x: x["site"])
        not_found_sites.sort(key=lambda x: x["site"])
        
        sorted_results = found_sites + not_found_sites

        summary = {
            "total_sites": len(results),
            "found_sites": len(found_sites),
            "not_found_sites": len(not_found_sites),
            "nsfw_sites_found": len([r for r in found_sites if r.get("isNSFW", False)]),
            "success_rate": f"{(len(found_sites)/len(results)*100):.1f}%" if results else "0%"
        }

        return {
            "target": username, 
            "status": "completed", 
            "sites": sorted_results,
            "summary": summary
        }
    
    except Exception as e:
        return {
            "target": username, 
            "status": "error", 
            "sites": [],
            "error": f"Scan failed: {str(e)}"
        }

# Test function
if __name__ == "__main__":
    test_username = "testuser"
    print(f"Testing optimized scanner with username: {test_username}")
    results = run(test_username)
    print(f"Status: {results['status']}")
    print(f"Found {len([r for r in results['sites'] if r['found']])} sites")
    for site in results['sites'][:5]:  # Show first 5 results
        print(f"  {site['site']}: {'FOUND' if site['found'] else 'Not found'}")