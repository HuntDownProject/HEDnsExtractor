package utils

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
	"net"
	"net/http/httputil"
	"regexp"
)

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
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
	}
}

func ExtractNetwork(ip string, silent bool, onlydomains bool, onlynetworks bool) {
	var urlBase = "https://bgp.he.net/"
	var url = ""

	if ip != "" {
		url = urlBase + "ip/" + ip
	}

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

	if ip != "" {
		var re = regexp.MustCompile(`(?m)href="/net/([^"]+)"`)
		for _, match := range re.FindAllStringSubmatch(str, -1) {
			if !contains(Networks, match[1]) {
				if (!silent && !onlydomains) || onlynetworks {
					gologger.Info().Msgf("[%s] %s\n", ip, match[1])
				}
				Networks = append(Networks, match[1])
			}
		}
	}
}

func ExtractDomains(ipRange string, silent bool, vtscore bool, vtscoreValue uint64) {
	var urlBase = "https://bgp.he.net/"
	var url = ""

	if ipRange != "" {
		url = urlBase + "net/" + ipRange
	}

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

	if ipRange != "" {
		var re = regexp.MustCompile(`(?m)href="/dns/([^"]+)"`)
		for _, match := range re.FindAllStringSubmatch(str, -1) {
			if silent {
				gologger.Silent().Msgf("%s\n", match[1])
			} else {
				if vtscore {
					Score := GetVtReport(match[1])
					if Score >= vtscoreValue {
						gologger.Info().Msgf("[%s] domain: %s VT Score: %d\n", ipRange, match[1], Score)
					}
				} else {
					gologger.Info().Msgf("[%s] domain: %s\n", ipRange, match[1])
				}
			}
		}
	}
}
