import re
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup

def get_page_response_with_selenium(url):
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"

    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1920x1080")
    chrome_options.add_argument(f"user-agent={user_agent}")

    chrome_options.add_argument("--enable-javascript")

    chrome_options.add_argument("--enable-cookies")

    driver = webdriver.Chrome(options=chrome_options)

    driver.get(url)

    driver.implicitly_wait(10)

    page_source = driver.page_source

    driver.quit()

    return page_source

def extract_domains_from_html(html_content):
    domains = []

    soup = BeautifulSoup(html_content, 'html.parser')
    dns_links = soup.select('a[href^="/dns/"]')

    for link in dns_links:
        domain_match = re.search(r'/dns/(.+)"', link['href'])
        if domain_match:
            domain = domain_match.group(1)
            domains.append(domain)

    return domains

if __name__ == "__main__":
    target_url = "https://bgp.he.net/net/104.21.0.0/19#_dns" 
    page_response = get_page_response_with_selenium(target_url)

    extracted_domains = extract_domains_from_html(page_response)

    print("Extracted Domains:")
    for domain in extracted_domains:
        print(domain)