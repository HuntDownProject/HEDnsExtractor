import re
import argparse
import json
import requests
from bs4 import BeautifulSoup
from random import randint
from time import sleep
from fake_useragent import UserAgent
from datetime import datetime

CONFIG_FILE = "config.json"

def load_config():
    with open(CONFIG_FILE) as f:
        config = json.load(f)
    return config

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

def convert_timestamp_to_date(timestamp):
    try:
        timestamp_int = int(timestamp)
        return datetime.utcfromtimestamp(timestamp_int).strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return "Not available"

def consult_vt(domain, vt_api_key):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "x-apikey": vt_api_key,
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        vt_data = response.json()
        attributes = vt_data.get("data", {}).get("attributes", {})
        last_analysis_stats = attributes.get("last_analysis_stats")
        category = attributes.get("categories", [])
        last_analysis_date = attributes.get("last_analysis_date")
        
        if last_analysis_stats:
            malicious = last_analysis_stats.get("malicious", 0)
            suspicious = last_analysis_stats.get("suspicious", 0)
            last_analysis_date_str = convert_timestamp_to_date(last_analysis_date)
            return int(malicious) + int(suspicious), category, last_analysis_date_str
    return None, category, "Not available"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Get the page source using requests with cookies, JS support, and random User-Agent.")
    parser.add_argument("target_url", help="The target URL.")
    parser.add_argument("--output-format", choices=["text", "json"], default="text", help="Output format (default: text)")
    parser.add_argument("--consult-vt", action="store_true", help="Query VirusTotal for domain scores.")
    args = parser.parse_args()

    target_url = args.target_url

    try:
        page_response = get_page_response_with_requests(target_url)
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        exit(1)

    domains = extract_domains_from_html(page_response)

    config = load_config()
    vt_api_key = config.get("vt_api_key")

    if args.consult_vt and vt_api_key:
        for domain in domains:
            score, categories, last_analysis_date = consult_vt(domain, vt_api_key)
            if score is not None:
                print(f"Domain: {domain}, VT Score: {score}, Last Analysis Date: {last_analysis_date}")
            else:
                print(f"Domain: {domain}, VT Score: Not available (VT API key may be missing)")

    if args.output_format == "json":
        domains_json = json.dumps(domains, indent=2)
        print(domains_json)
    else:
        for domain in domains:
            print(domain)

    sleep(randint(1, 3))