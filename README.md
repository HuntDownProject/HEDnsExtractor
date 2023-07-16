# example usage:
1. Extract all domains and use httpx to search for specific value
   
python HEDnsExtractor.py "https://bgp.he.net/net/104.21.0.0/19#_dns" | grep -o '/dns/[^"]\+"' | cut -d "/" -f 3 | sed 's/"$//' | httpx -title -tech-detect -status-code | grep -i "your search"

![image](https://raw.githubusercontent.com/teixeira0xfffff/HEDnsExtractor/main/assets/sample.png)
