import re
import json
import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from datetime import datetime
import typer
from typing import Tuple, List

CONFIG_FILE = "config.json"

app = typer.Typer()


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

def extract_networks_from_html(html_content):
    domains = []
    soup = BeautifulSoup(html_content, 'lxml')
    dns_links = soup.select('a[href^="/net/"]')

    for link in dns_links:
        domain_match = re.finditer(r'/net/(.*)', link['href'], re.MULTILINE)
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


def query_vt(domain, vt_api_key):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = { "x-apikey": vt_api_key}
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
    return None, "", "Not available"


@app.command()
def networks(ip_address: str):
    target_url = f"https://bgp.he.net/ip/{ip_address}"
    try:
        page_response = get_page_response_with_requests(target_url)
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        exit(1)

    networks = extract_networks_from_html(page_response)
    for network in networks:
        print(network)

@app.command()
def domains(ip_range: str, consult_vt: bool = False, json_dump : bool = False):
    target_url = f"https://bgp.he.net/net/{ip_range}#_dns"

    try:
        page_response = get_page_response_with_requests(target_url)
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        exit(1)

    domains = extract_domains_from_html(page_response)

    listof_tuples : List[Tuple] = []

    if consult_vt:
        config = load_config()
        vt_api_key = config.get("vt_api_key")
        if not vt_api_key:
            return  # TODO: logar erro
        
        for domain in domains:
            score, categories, last_analysis_date = query_vt(domain, vt_api_key)
            listof_tuples.append((domain, score, categories, last_analysis_date))
    else:
        for domain in domains:
            listof_tuples.append((domain, 0, {}, ""))

    if not json_dump:
        for domain, score, categories, last_analysis_date in listof_tuples:
            log_raw(domain, score, categories, last_analysis_date)
    else:
        log_json(ip_range, listof_tuples)


def log_json(ip_range: str, domains: List):
    doc = {'ip_range': ip_range, 'domains': []}
    for domain, score, categories, last_analysis_date in domains:
        item = {
            'domain': domain,
            'score': score,
            'categories': categories,
            'last_analysis_date': last_analysis_date
        }
        doc['domains'].append(item)
    output = json.dumps(doc)
    print(output)

def log_raw(domain: str, score: int, categories: dict, last_analysis_date: str):
    if score is not None:
        print(f"Domain: {domain}, VT Score: {score}, category: {categories}, Last Analysis Date: {last_analysis_date}")
    else:
        print(f"Domain: {domain}, VT Score: Not available (VT API key may be missing)")


if __name__ == "__main__":
    app()
