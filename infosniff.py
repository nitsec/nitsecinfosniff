import requests
from bs4 import BeautifulSoup
import re
import tldextract
from urllib.parse import urljoin, urlparse

visited = set()
found_sensitive = []

def load_file(file_path):
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]

def get_links(url):
    try:
        resp = requests.get(url, timeout=5)
        soup = BeautifulSoup(resp.text, "html.parser")
        links = set()
        for a in soup.find_all("a", href=True):
            link = urljoin(url, a['href'])
            if is_same_domain(url, link):
                links.add(link.split('#')[0])
        return links
    except:
        return set()

def is_same_domain(base, target):
    base_host = tldextract.extract(base).registered_domain
    target_host = tldextract.extract(target).registered_domain
    return base_host == target_host

def scan_url(url, patterns):
    try:
        resp = requests.get(url, timeout=5)
        content = resp.text.lower()
        for keyword in patterns:
            if keyword.lower() in content:
                print(f"[!] Sensitive content found in: {url}  ->  Keyword: {keyword}")
                found_sensitive.append((url, keyword))
    except:
        pass

def crawl_and_fuzz(base_url, wordlist, sensitive_words):
    queue = set([base_url])
    while queue:
        current_url = queue.pop()
        if current_url in visited:
            continue
        visited.add(current_url)

        print(f"[+] Crawling: {current_url}")
        scan_url(current_url, sensitive_words)

        links = get_links(current_url)
        queue.update(links)

    print("\n[+] Starting Fuzzing...")
    for path in wordlist:
        test_url = urljoin(base_url + "/", path)
        scan_url(test_url, sensitive_words)

    print("\n[✓] Scan complete.")
    if found_sensitive:
        print("\n[!] Sensitive URLs:")
        for url, keyword in found_sensitive:
            print(f"- {url}   | keyword: {keyword}")
    else:
        print("[+] No sensitive content found.")

if __name__ == "__main__":
    target = input("Enter target URL (e.g., https://example.com): ").strip()
    wordlist = load_file("wordlist.txt")
    sensitive_words = load_file("sensitive_words.txt")
    crawl_and_fuzz(target, wordlist, sensitive_words)
