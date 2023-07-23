import re
import argparse
import json
import requests
from bs4 import BeautifulSoup
from random import randint
from time import sleep
from fake_useragent import UserAgent

def get_page_response_with_requests(url):
    ua = UserAgent()
    headers = {
        "User-Agent": ua.random,
    }
    session = requests.Session()
    session.headers.update(headers)
    response = session.get(url)
    response.raise_for_status()
    return response.text

def extract_domains_from_html(html_content):
    domains = []
    soup = BeautifulSoup(html_content, 'lxml')
    dns_links = soup.select('a[href^="/dns/"]')

    for link in dns_links:
        domain_match = re.finditer(r"\/dns\/(.+)", link['href'], re.MULTILINE)
        for match in domain_match:
            domain = match.group(1)
            domains.append(domain)

    return domains

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Get the page source using requests with cookies, JS support, and random User-Agent.")
    parser.add_argument("target_url", help="The target URL.")
    parser.add_argument("--output-format", choices=["text", "json"], default="text", help="Output format (default: text)")
    args = parser.parse_args()

    target_url = args.target_url

    try:
        page_response = get_page_response_with_requests(target_url)
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        exit(1)

    domains = extract_domains_from_html(page_response)

    if args.output_format == "json":
        domains_json = json.dumps(domains, indent=2)
        print(domains_json)
    else:
        for domain in domains:
            print(domain)

    sleep(randint(1, 3))