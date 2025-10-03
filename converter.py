import json

def extract_urls(json_file, output_file="urls.txt"):
    # Load JSON
    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    urls = []

    # Iterate over all sites
    for sitename, info in data.items():
        if "url" in info:
            urls.append(info["url"])

    # Save to file
    with open(output_file, "w", encoding="utf-8") as f:
        for url in urls:
            f.write(url + "\n")

    return urls


if __name__ == "__main__":
    urls = extract_urls("users.json")
    print(f"Extracted {len(urls)} URLs. Saved to urls.txt")
