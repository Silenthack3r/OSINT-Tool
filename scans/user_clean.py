import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import re

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

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}

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
    """Check a single site with proper error detection."""
    # Check regex first
    regex_pattern = info.get("regexCheck")
    if not check_username_regex(username, regex_pattern):
        return {"site": sitename, "url": info["url"].format(username), "found": False, "reason": "regex_fail"}

    urls_to_try = [info["url"].format(username)]  # original username
    
    # Add mutated usernames if no regex restriction
    if not regex_pattern:
        for variant in mutate_username(username):
            urls_to_try.append(info["url"].format(variant))

    for url in urls_to_try:
        try:
            # Handle special request types
            if info.get("request_method") == "POST":
                if "request_payload" in info:
                    payload = info["request_payload"]
                    # Replace username placeholder in payload
                    payload_str = json.dumps(payload).replace("{}", username)
                    payload = json.loads(payload_str)
                    response = requests.post(
                        info.get("urlProbe", url),
                        json=payload,
                        headers=HEADERS,
                        timeout=10,
                        allow_redirects=True
                    )
                else:
                    continue
            else:
                # Normal GET request
                response = requests.get(
                    url, 
                    headers=HEADERS, 
                    timeout=10, 
                    allow_redirects=True
                )

            found = False
            error_type = info.get("errorType", "status_code")

            if error_type == "status_code":
                # 200 status usually means found, 404 means not found
                if response.status_code == 200:
                    found = True
                elif response.status_code == 404:
                    found = False
                else:
                    # For other status codes, check content
                    error_msg = info.get("errorMsg", "")
                    if isinstance(error_msg, list):
                        if not any(msg in response.text for msg in error_msg):
                            found = True
                    elif error_msg and error_msg not in response.text:
                        found = True

            elif error_type == "message":
                error_msg = info.get("errorMsg", "")
                if isinstance(error_msg, list):
                    if not any(msg in response.text for msg in error_msg):
                        found = True
                elif error_msg and error_msg not in response.text:
                    found = True

            # Additional check for response content
            if found and response.status_code != 200:
                found = False

            if found:
                return {
                    "site": sitename, 
                    "url": url, 
                    "found": True,
                    "urlMain": info.get("urlMain", ""),
                    "isNSFW": info.get("isNSFW", False)
                }

        except requests.exceptions.Timeout:
            continue  # Try next mutation or skip
        except requests.exceptions.RequestException:
            continue  # Try next mutation or skip
        except Exception as e:
            continue  # Try next mutation or skip

    return {
        "site": sitename, 
        "url": info["url"].format(username), 
        "found": False,
        "urlMain": info.get("urlMain", ""),
        "isNSFW": info.get("isNSFW", False)
    }

def run(username):
    """Run all site checks in parallel."""
    if not DATA:
        return {
            "target": username, 
            "status": "error", 
            "sites": [],
            "error": "users.json not loaded properly"
        }
    
    results = []
    try:
        with ThreadPoolExecutor(max_workers=15) as executor:  # Conservative thread count
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
                    
                    # Optional: Print progress
                    if completed % 10 == 0:
                        print(f"Progress: {completed}/{total} sites checked")
                        
                except Exception as e:
                    print(f"Error processing site: {e}")
                    continue

        # Sort results: found sites first, then alphabetically
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

# Test function for debugging
if __name__ == "__main__":
    test_username = "testuser"
    print(f"Testing scanner with username: {test_username}")
    results = run(test_username)
    print(f"Status: {results['status']}")
    print(f"Found {len([r for r in results['sites'] if r['found']])} sites")
    for site in results['sites'][:5]:  # Show first 5 results
        print(f"  {site['site']}: {'FOUND' if site['found'] else 'Not found'}")