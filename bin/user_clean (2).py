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

async def check_site_async(session, username, sitename, info):
    """ULTRA FAST async site checker"""
    # Fast regex check first
    regex_pattern = info.get("regexCheck")
    if regex_pattern:
        try:
            if not re.match(regex_pattern, username):
                return {"site": sitename, "url": info["url"].format(username), "found": False, "reason": "regex_fail"}
        except:
            pass

    url = info["url"].format(username=username)
    
    try:
        # FIRE THE REQUEST - 3 second timeout max
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=3)) as response:
            resp_code = response.status
            resp_text = await response.text()
            
            # ULTRA FAST validation
            if resp_code == 200:
                # Quick content check
                text_snippet = (resp_text or "").lower()[:1000]
                
                # Fast error detection
                error_indicators = ["not found", "404", "doesn't exist", "no such user", "error"]
                if not any(error in text_snippet for error in error_indicators):
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
    except Exception:
        return {"site": sitename, "url": url, "found": False, "reason": "error"}

async def run_async_scan(username):
    """MAIN ASYNC SCANNER - Fires all requests simultaneously"""
    if not DATA:
        return {
            "target": username, 
            "status": "error", 
            "sites": [],
            "error": "users.json not loaded properly"
        }
    
    print(f"🚀 Starting ULTRA FAST async scan for: {username}")
    start_time = time.time()
    results = []
    
    # Create session with connection limits suitable for low memory
    connector = aiohttp.TCPConnector(limit=100, limit_per_host=10)
    
    async with aiohttp.ClientSession(
        connector=connector,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        },
        timeout=aiohttp.ClientTimeout(total=3)
    ) as session:
        
        # CREATE ALL TASKS AT ONCE
        tasks = []
        valid_sites = 0
        
        for sitename, info in DATA.items():
            if "url" not in info:
                continue
                
            task = check_site_async(session, username, sitename, info)
            tasks.append(task)
            valid_sites += 1
        
        print(f"🎯 Firing {valid_sites} simultaneous requests...")
        
        # EXECUTE ALL REQUESTS CONCURRENTLY
        completed = 0
        found_count = 0
        
        for future in asyncio.as_completed(tasks):
            try:
                result = await future
                results.append(result)
                completed += 1
                
                if result["found"]:
                    found_count += 1
                
                # Progress update every 25 sites
                if completed % 25 == 0:
                    elapsed = time.time() - start_time
                    print(f"📊 Progress: {completed}/{valid_sites} sites | Found: {found_count} | Time: {elapsed:.1f}s")
                    
            except Exception:
                completed += 1
                continue
    
    # Calculate performance
    end_time = time.time()
    total_time = end_time - start_time
    
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
        "success_rate": f"{(len(found_sites)/len(results)*100):.1f}%" if results else "0%",
        "scan_time_seconds": f"{total_time:.1f}",
        "sites_per_second": f"{(len(results)/total_time):.1f}" if total_time > 0 else "N/A"
    }

    print(f"🎉 Scan completed in {total_time:.1f}s - Found {len(found_sites)} sites")
    
    return {
        "target": username, 
        "status": "completed", 
        "sites": sorted_results,
        "summary": summary
    }

# Synchronous wrapper for Flask compatibility
def run(username):
    """Wrapper to run the async scanner - THIS IS WHAT YOUR FLASK APP CALLS"""
    print(f"🔥 Starting ULTRA FAST scan for: {username}")
    return asyncio.run(run_async_scan(username))

# For testing
if __name__ == "__main__":
    test_username = "testuser"
    results = run(test_username)
    print(f"Found {len([r for r in results['sites'] if r['found']])} sites")