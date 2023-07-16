# sample usage:


python HEDnsExtractor.py | grep -o '/dns/[^"]\+"' | cut -d "/" -f 3 | sed 's/"$//' | httpx -title -tech-detect -status-code | grep -i "your search"
