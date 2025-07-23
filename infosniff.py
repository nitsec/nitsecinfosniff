import requests
from bs4 import BeautifulSoup
import tldextract
from urllib.parse import urljoin
import re

visited = set()
found_sensitive = []

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/115.0 Safari/537.36"
}

regex_patterns = [
    r'AKIA[0-9A-Z]{16}',  # AWS Access Key ID
    r'(?i)eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',  # JWT token
    r'-----BEGIN PRIVATE KEY-----',  # Private key PEM
    r'AIza[0-9A-Za-z-_]{35}',  # Google API key
]

def load_file(file_path):
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]

def get_all_links(url):
    try:
        resp = requests.get(url, headers=HEADERS, timeout=5)
        soup = BeautifulSoup(resp.text, "html.parser")
        links = set()
        for a in soup.find_all("a", href=True):
            link = urljoin(url, a['href'])
            if is_same_domain(url, link):
                links.add(link.split('#')[0])
        return links
    except Exception as e:
        print(f"[!] Error getting links from {url}: {e}")
        return set()

def is_same_domain(base, target):
    base_host = tldextract.extract(base).registered_domain
    target_host = tldextract.extract(target).registered_domain
    return base_host == target_host

def filter_links_by_extension(links, exts):
    filtered = set()
    for link in links:
        for ext in exts:
            if link.lower().endswith(ext):
                filtered.add(link)
    return filtered

def scan_url(url, patterns):
    try:
        resp = requests.get(url, headers=HEADERS, timeout=5)
        content = resp.text
        lowered = content.lower()
        for keyword in patterns:
            if keyword.lower() in lowered:
                print(f"[!] Sensitive content found in: {url}  ->  Keyword: {keyword}")
                found_sensitive.append((url, keyword))
        for regex in regex_patterns:
            if re.search(regex, content):
                print(f"[!] Sensitive content matched regex in: {url}  ->  Pattern: {regex}")
                found_sensitive.append((url, regex))
    except Exception as e:
        print(f"[!] Error scanning {url}: {e}")

def crawl_and_fuzz(base_url, wordlist, sensitive_words):
    print(f"[+] Crawling base URL: {base_url}")
    all_links = get_all_links(base_url)
    print(f"[+] Crawled {len(all_links)} links.")

    exts_to_find = ['.txt', '.js', '.zip', '.php']
    filtered_links = filter_links_by_extension(all_links, exts_to_find)
    print(f"[+] Filtered {len(filtered_links)} links with target extensions.")

    if filtered_links:
        print(f"[+] Found {len(filtered_links)} links with target extensions. Scanning them...")
        for url in filtered_links:
            scan_url(url, sensitive_words)
    else:
        print(f"[+] No target extension links found. Starting fuzzing {len(wordlist)} paths...")
        for path in wordlist:
            fuzz_url = urljoin(base_url + "/", path)
            scan_url(fuzz_url, sensitive_words)

    print("[✓] Scan complete.")
    if found_sensitive:
        print("\n[!] Sensitive URLs found:")
        for url, keyword in found_sensitive:
            print(f"- {url}  | keyword: {keyword}")
    else:
        print("[+] No sensitive content found.")

if __name__ == "__main__":
    target = input("Enter target URL (e.g., https://example.com): ").strip()
    wordlist = load_file("wordlist.txt")
    sensitive_words = load_file("sensitive_words.txt")
    crawl_and_fuzz(target, wordlist, sensitive_words)


