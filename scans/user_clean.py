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

    # Build list of (url, probe_username) so POST payloads can use the
    # correct username variant when substituting. This prevents mismatch
    # between URL and payload which can lead to false positives.
    urls_to_try = [(info["url"].format(username), username)]

    # Add mutated usernames if no regex restriction
    if not regex_pattern:
        for variant in mutate_username(username):
            urls_to_try.append((info["url"].format(variant), variant))

    # Optional probe cache for baseline (helps detect sites that return a
    # generic page for missing users). Controlled per-site via
    # `info["probe"] = True` to avoid extra requests unless configured.
    PROBE_CACHE = globals().get("_USER_CLEAN_PROBE_CACHE")
    if PROBE_CACHE is None:
        PROBE_CACHE = {}
        globals()["_USER_CLEAN_PROBE_CACHE"] = PROBE_CACHE

    for url, probe_username in urls_to_try:
        try:
            # Handle special request types
            if info.get("request_method") == "POST":
                if "request_payload" in info:
                    payload = info["request_payload"]
                    # Replace username placeholder in payload. Support
                    # a clearer placeholder `{username}`; fall back to
                    # `{}` if necessary. Use the probe_username (the
                    # variant we're testing), not the original username.
                    payload_str = json.dumps(payload)
                    if "{username}" in payload_str:
                        payload_str = payload_str.replace("{username}", probe_username)
                    else:
                        payload_str = payload_str.replace("{}", probe_username)
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

            # Redirect heuristic: if the request ended up at the site root
            # or a login/dashboard path, it's likely a generic page and not
            # a profile. Sites can override via `invalidRedirects`.
            try:
                orig = urlparse(url)
                final = urlparse(response.url)
                invalid_redirects = info.get("invalidRedirects", [])
                redirected_to_generic = False
                if response.url != url and orig.netloc == final.netloc:
                    path = (final.path or "/").lower()
                    if path in ["/", ""] or any(p in path for p in ["login", "signin", "signup", "dashboard"]):
                        redirected_to_generic = True
                    if any(pat in response.url for pat in invalid_redirects):
                        redirected_to_generic = True

                if redirected_to_generic:
                    # Treat as not found for this probe/variant and continue
                    if info.get("debug", False):
                        print(f"Redirected to generic page for {sitename}: {response.url}")
                    continue
            except Exception:
                # Non-fatal; proceed to content checks
                pass

            # --- Validation Phase ---
            # Fast and accurate response evaluation to reduce false positives
            resp_code = response.status_code
            resp_text = response.text or ""
            resp_len = len(resp_text)

            # Fast short-circuit: ignore redirects or empty pages
            if resp_code in (301, 302, 303, 307, 308) or resp_len < 100:
                continue

            # Quick redirect detection (expanded list)
            final_url = response.url.lower()
            path = urlparse(final_url).path
            GENERIC_PATHS = ["login", "signin", "signup", "register", "home", "dashboard", "index"]
            if any(p in path for p in GENERIC_PATHS):
                continue
            if any(p in final_url for p in info.get("invalidRedirects", [])):
                continue

            # --- Smart content analysis ---
            # Convert a small, relevant slice to lowercase once
            snippet = (resp_text[:8000] + resp_text[-8000:]).lower() if resp_len > 16000 else resp_text.lower()

            error_msgs = info.get("errorMsg", [])
            if isinstance(error_msgs, str):
                error_msgs = [error_msgs]

            contains_error = any(msg.lower() in snippet for msg in error_msgs if msg)
            if not contains_error:
                # common not-found phrases (generic fallback)
                COMMON_404 = ["user not found", "page not found", "no such user", "doesn't exist", "not exist", "404"]
                contains_error = any(msg in snippet for msg in COMMON_404)

            # --- Fast structural checks (length + hash) ---
            # Cache baseline probe to detect generic pages
            cache_key = f"{sitename}:{info['url']}"
            PROBE_CACHE = globals().setdefault("_USER_CLEAN_PROBE_CACHE", {})
            baseline = PROBE_CACHE.get(cache_key)

            if info.get("probe", False) and baseline is None:
                try:
                    probe_name = f"__probe_{uuid4().hex}__"
                    probe_url = info["url"].format(probe_name)
                    probe_resp = requests.get(probe_url, headers=HEADERS, timeout=6)
                    probe_text = probe_resp.text or ""
                    probe_snip = (probe_text[:8000] + probe_text[-8000:]).lower()
                    PROBE_CACHE[cache_key] = probe_snip
                    baseline = probe_snip
                except Exception:
                    pass

            found = False

            # --- Decision tree ---
            if resp_code == 404 or contains_error:
                found = False
            elif resp_code == 200:
                found = True
                if baseline:
                    # Quick compare via length + ratio + token overlap
                    base_len = len(baseline)
                    len_diff = abs(resp_len - base_len)
                    if len_diff < 200:
                        found = False
                    else:
                        # Fast difflib ratio check (optimized for short snippet)
                        ratio = difflib.SequenceMatcher(None, baseline, snippet).quick_ratio()
                        if ratio > 0.90:
                            found = False
                        else:
                            # Token overlap as final guard
                            base_words = set(re.findall(r'\w+', baseline))
                            cur_words = set(re.findall(r'\w+', snippet))
                            overlap = len(base_words & cur_words) / max(1, len(cur_words))
                            if overlap > 0.8:
                                found = False
            else:
                found = (resp_code < 400 and not contains_error)

            # Skip heavy diffs early for speed
            if not found:
                continue

            # Return found site
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