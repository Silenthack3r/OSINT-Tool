import requests
from bs4 import BeautifulSoup
import re

# Tor proxy (Tor must be running)
proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

def extract_links(text):
    """Extracts onion and normal web links from text using regex."""
    url_pattern = r"(https?://[^\s]+|[a-z2-7]{16,56}\.onion[^\s]*)"
    return re.findall(url_pattern, text)

def search_onion_links(keyword):
    """Search .onion site and return links only."""
    # Replace with your .onion search engine URL
    onion_search_url = "http://torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd.onion/search?query={query}"
    results_list = []

    try:
        search_url = onion_search_url.format(query=keyword)
        response = requests.get(search_url, proxies=proxies, timeout=30)

        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            results = []

            for link in soup.find_all("a", href=True):
                results.append({
                    "text": link.get_text(strip=True),
                    "url": link['href']
                })

            # Only extract links (links-only mode)
            clean_links = []
            for r in results:
                found = extract_links(r['text'] + " " + r['url'])
                clean_links.extend(found)

            clean_links = list(set(clean_links))  # remove duplicates
            results_list = clean_links[:20]       # limit to 20 links

        else:
            results_list = [f"Request failed with status {response.status_code}"]

    except Exception as e:
        results_list = [f"Error: {e}"]

    return results_list

# Optional: testing
if __name__ == "__main__":
    test_keyword = "test"
    links = search_onion_links(test_keyword)
    print(links)
