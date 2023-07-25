<p align="center">
  <img src="assets/logo.png">
</p>

<h1 align="center">HEDnsExtractor</h1>
<p align="center">
  <a href="https://python.org/">
    <img src="https://img.shields.io/pypi/pyversions/3.svg">
  </a>
    <a href="https://opensource.org">
    <img src="https://img.shields.io/badge/Open%20Source-%E2%9D%A4-brightgreen.svg">
  </a>
</p>

<p align="center">
  Raw html extractor from Hurricane Electric portal
</p>


#JSON Format output

python3.10 HEDnsExtractor.py "https://bgp.he.net/net/81.82.0.0/15#_dns" --output-format json

# example usage:
1. Extract all domains and use httpx to search for specific value
   
python HEDnsExtractor.py "https://bgp.he.net/net/104.21.0.0/19#_dns" | httpx -title -tech-detect -status-code | grep -i "your search"

<p align="center">
  <img src="assets/sample.png">
</p>

# 2. Phishing Hunting
   <p align="center">
  <img src="assets/intelhed.jpeg">
</p>
