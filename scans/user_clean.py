import json
import aiohttp
import asyncio
import os
import re
import time

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


    def validate_users_json(data):
        """Basic validation of users.json entries to detect common misconfigurations.
        - Warn if an entry has no URL placeholder
        - Warn if entries use mixed placeholder styles across the file
        """
        if not isinstance(data, dict):
            print("Warning: users.json should be an object/dictionary of sites")
            return

        uses_positional = False
        uses_named = False
        for sitename, info in data.items():
            url = info.get("url") if isinstance(info, dict) else None
            if not url:
                print(f"Warning: site '{sitename}' missing 'url' field in users.json")
                continue
            if "{}" in url:
                uses_positional = True
            if "{username}" in url:
                uses_named = True
            if "{}" not in url and "{username}" not in url:
                # Not fatal, but warn: URL may be static or require different formatting
                print(f"Warning: site '{sitename}' url does not contain a username placeholder: {url}")

        if uses_positional and uses_named:
            print("Warning: users.json uses both positional '{}' and named '{username}' placeholders; this can cause formatting confusion. Consider standardizing to '{username}'.")


    # Run a validation at import time to surface issues early
    validate_users_json(DATA)


def _format_url(template, username):
    """Safely format URL templates that may use positional '{}' or named '{username}' placeholders.
    Tries several strategies and falls back to a simple replace if formatting fails.
    """
    if not template:
        return template
    try:
        # If explicit named placeholder present, use it
        if "{username}" in template:
            return template.format(username=username)
        # If positional placeholder used
        if "{}" in template:
            return template.format(username)
        # Try keyword formatting first (most explicit)
        try:
            return template.format(username=username)
        except Exception:
            return template.format(username)
    except Exception:
        # Last resort: replace common placeholder patterns
        try:
            return template.replace("{username}", username).replace("{}", username)
        except Exception:
            return template

async def check_site_async(session, username, sitename, info):
    """Fast but reliable site checker"""
    # Fast regex check first
    regex_pattern = info.get("regexCheck")
    if regex_pattern:
        try:
            if not re.match(regex_pattern, username):
                return {"site": sitename, "url": _format_url(info.get("url", ""), username), "found": False, "reason": "regex_fail"}
        except:
            pass

    url = _format_url(info.get("url", ""), username)
    
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=4)) as response:
            resp_code = response.status
            resp_text = await response.text()
            
            # Proper validation
            if resp_code == 200:
                text_snippet = (resp_text or "").lower()[:1500]
                
                # Check for error messages
                error_msgs = info.get("errorMsg", [])
                if isinstance(error_msgs, str):
                    error_msgs = [error_msgs]
                
                contains_error = any(msg.lower() in text_snippet for msg in error_msgs if msg)
                
                # Common error patterns as fallback
                if not contains_error:
                    common_errors = ["not found", "404", "doesn't exist", "no such user", "error", "page not found"]
                    contains_error = any(error in text_snippet for error in common_errors)
                
                if not contains_error:
                    return {
                        "site": sitename,
                        "url": url,
                        "found": True,
                        "urlMain": info.get("urlMain", ""),
                        "isNSFW": info.get("isNSFW", False)
                    }
            
            return {
                "site": sitename,
                "url": url,
                "found": False,
                "urlMain": info.get("urlMain", ""),
                "isNSFW": info.get("isNSFW", False)
            }
            
    except asyncio.TimeoutError:
        return {"site": sitename, "url": url, "found": False, "reason": "timeout"}
    except Exception as e:
        return {"site": sitename, "url": url, "found": False, "reason": f"error: {str(e)}"}

async def run_async_scan(username):
    """Scan ALL domains with real-time progress"""
    if not DATA:
        return {
            "target": username, 
            "status": "error", 
            "sites": [],
            "error": "users.json not loaded properly"
        }
    
    print(f"🎯 Starting comprehensive scan for: {username}")
    start_time = time.time()
    
    # Get ALL sites from JSON
    sites_to_check = []
    for sitename, info in DATA.items():
        if "url" in info:
            sites_to_check.append((sitename, info))
    
    total_sites = len(sites_to_check)
    print(f"📊 Scanning ALL {total_sites} platforms from JSON file...")
    
    # Balanced connection settings for speed and reliability
    connector = aiohttp.TCPConnector(limit=50, limit_per_host=10)
    
    async with aiohttp.ClientSession(
        connector=connector,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        },
        timeout=aiohttp.ClientTimeout(total=4)
    ) as session:
        
        # Create tasks for ALL sites
        tasks = []
        for sitename, info in sites_to_check:
            task = check_site_async(session, username, sitename, info)
            tasks.append(task)
        
        print(f"🚀 Firing {len(tasks)} requests to check ALL platforms...")
        
        # Process results as they come in with real-time progress
        results = []
        found_count = 0
        completed = 0
        
        for future in asyncio.as_completed(tasks):
            try:
                result = await future
                results.append(result)
                completed += 1
                
                if result["found"]:
                    found_count += 1
                    print(f"✅ FOUND: {result['site']}")
                
                # Show progress updates
                if completed % 20 == 0:  # Update every 20 sites
                    elapsed = time.time() - start_time
                    progress_percent = (completed / total_sites) * 100
                    sites_per_sec = completed / elapsed if elapsed > 0 else 0
                    
                    print(f"📈 Progress: {completed}/{total_sites} ({progress_percent:.1f}%) | "
                          f"Found: {found_count} | Speed: {sites_per_sec:.1f} sites/sec | "
                          f"Time: {elapsed:.1f}s")
                    
            except Exception as e:
                completed += 1
                print(f"❌ Error checking site: {e}")
                continue
    
    # Scan completed
    end_time = time.time()
    total_time = end_time - start_time
    
    print(f"\n🎉 SCAN COMPLETED!")
    print(f"⏰ Total time: {total_time:.1f} seconds")
    print(f"📊 Sites scanned: {len(results)}")
    print(f"✅ Found on: {found_count} platforms")
    print(f"⚡ Average speed: {len(results)/total_time:.1f} sites/second")
    
    # Sort results: found sites first, then by site name
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
        "success_rate": f"{(len(found_sites)/len(results)*100):.1f}%" if results else "0%",
        "scan_time_seconds": f"{total_time:.1f}",
        "sites_per_second": f"{(len(results)/total_time):.1f}" if total_time > 0 else "N/A"
    }

    return {
        "target": username, 
        "status": "completed", 
        "sites": sorted_results,
        "summary": summary
    }

# Synchronous wrapper for Flask compatibility
def run(username):
    """Main function called by your Flask app - scans ALL domains and returns immediately when done"""
    print(f"🔥 Starting username scan for: {username}")
    return asyncio.run(run_async_scan(username))

# For testing
if __name__ == "__main__":
    test_username = "testuser"
    print("🚀 TESTING COMPREHENSIVE SCANNER")
    print("=" * 60)
    
    results = run(test_username)
    
    print(f"\n📋 FINAL RESULTS:")
    print(f"Target: {results['target']}")
    print(f"Status: {results['status']}")
    print(f"Total sites checked: {results['summary']['total_sites']}")
    print(f"Found on: {results['summary']['found_sites']} sites")
    print(f"Scan time: {results['summary']['scan_time_seconds']} seconds")
    
    # Show first 10 found sites
    found_sites = [r for r in results['sites'] if r['found']]
    if found_sites:
        print(f"\n📍 Found on these platforms:")
        for site in found_sites[:15]:
            print(f"   ✓ {site['site']}")