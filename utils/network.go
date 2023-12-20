package utils

import (
	"bufio"
	"io"
	"net"
	"net/http/httputil"
	"os"
	"regexp"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
	fileutil "github.com/projectdiscovery/utils/file"

	"github.com/PuerkitoBio/goquery"
)

func Contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func ParseStdin() {
	// Look into stdin to grab the IPv4s and Networks
	if fileutil.HasStdin() {
		s := bufio.NewScanner(os.Stdin)
		for s.Scan() {
			IdentifyTarget(s.Text())
		}
	}
}

func IsIpAddr(ipAddr string) bool {
	addr := net.ParseIP(ipAddr)
	return addr != nil
}

func IsIpNet(ipAddr string) bool {
	addr, _, _ := net.ParseCIDR(ipAddr)
	return addr != nil
}

func IdentifyTarget(target string) {
	isNetwork := IsIpNet(target)
	if isNetwork {
		Networks = append(Networks, target)
	}

	if !isNetwork && IsIpAddr(target) {
		Hosts = append(Hosts, target)
	} else {
		Domains = append(Domains, target)
	}
}

func Request(url string) string {
	opts := retryablehttp.DefaultOptionsSpraying
	client := retryablehttp.NewClient(opts)
	resp, err := client.Get(url)
	if err != nil {
		panic(err)
	}

	bin, err := httputil.DumpResponse(resp, true)
	if err != nil {
		panic(err)
	}
	str := string(bin)

	return str
}

func ParseHTML(body io.Reader) {
	doc, err := goquery.NewDocumentFromReader(body)
	if err != nil {
		gologger.Fatal().Msgf("%s", err)
	}

	var re = regexp.MustCompile(`\/dns\/([^"]+)`)

	doc.Find("#dnsrecords").Each(func(h int, div *goquery.Selection) {
		div.Find("tr").Each(func(i int, tr *goquery.Selection) {
			var result Result
			tr.Find("td").Each(func(j int, td *goquery.Selection) {
				td.Find("a").Each(func(k int, a *goquery.Selection) {
					switch td.Index() {
					case 0:
						result.IPAddr = a.Text()
					case 1:
						result.PTR = a.Text()
					case 2:
						html, err := td.Html()
						if err == nil {
							for _, match := range re.FindAllStringSubmatch(html, -1) {
								result.Domain = match[1]
								Results[result.Domain] = result
							}
						}
					}
				})
			})
		})
	})
}

func ExtractDomain(domain string, silent bool) {
	var url = ""

	if domain != "" {
		url = urlBase + "dns/" + domain
	}

	var str = Request(url)

	var re = regexp.MustCompile(`(?m)href="/net/([^"]+)"`)
	for _, match := range re.FindAllStringSubmatch(str, -1) {
		if !Contains(Networks, match[1]) {
			if (!silent && !OptionCmd.Onlydomains) || OptionCmd.Onlynetworks {
				gologger.Info().Msgf("[%s] network: %s\n", domain, match[1])
			}
			Networks = append(Networks, match[1])
		}
	}
}

func ExtractNetwork(ip string, silent bool, onlydomains bool, onlynetworks bool) {
	var url = ""

	if ip != "" {
		url = urlBase + "ip/" + ip
	}

	var str = Request(url)

	if ip != "" {
		var re = regexp.MustCompile(`(?m)href="/net/([^"]+)"`)
		for _, match := range re.FindAllStringSubmatch(str, -1) {
			if !Contains(Networks, match[1]) {
				if (!silent && !onlydomains) || onlynetworks {
					gologger.Info().Msgf("[%s] network: %s\n", ip, match[1])
				}
				Networks = append(Networks, match[1])
			}
		}
	}
}

func ExtractDomains(ipRange string) {
	if ipRange == "" {
		return
	}

	var url = urlBase + "net/" + ipRange
	var html = Request(url)

	ParseHTML(strings.NewReader(html))
}

func RunCrawler() {
	for _, domain := range Domains {
		gologger.Verbose().Msgf("Identifying networks for domain: %s", domain)
		ExtractDomain(domain, OptionCmd.Silent)
	}

	for _, host := range Hosts {
		gologger.Verbose().Msgf("Identifying networks for IPv4: %s", host)
		ExtractNetwork(
			host,
			OptionCmd.Silent,
			OptionCmd.Onlydomains,
			OptionCmd.Onlynetworks)
	}

	if !OptionCmd.Onlynetworks {
		for _, network := range Networks {
			gologger.Verbose().Msgf("Identifying domains for network: %s", network)
			ExtractDomains(network)
		}
	}
}
