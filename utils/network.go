package utils

import (
	"bufio"
	"net"
	"net/http/httputil"
	"os"
	"regexp"
	"strconv"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
	fileutil "github.com/projectdiscovery/utils/file"
)

func contains(s []string, e string) bool {
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

func ExtractDomain(domain string, silent bool) {
	var url = ""

	if domain != "" {
		url = urlBase + "dns/" + domain
	}

	var str = Request(url)

	var re = regexp.MustCompile(`(?m)href="/net/([^"]+)"`)
	for _, match := range re.FindAllStringSubmatch(str, -1) {
		if !contains(Networks, match[1]) {
			if !silent {
				gologger.Info().Msgf("[%s] %s\n", domain, match[1])
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
	var url = ""

	if ipRange != "" {
		url = urlBase + "net/" + ipRange
	}

	var str = Request(url)

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

func RunCrawler() {
	if len(Domains) > 0 {
		for i := range Domains {
			ExtractDomain(Domains[i], OptionCmd.Silent)
		}
	}

	if len(Hosts) > 0 {
		for i := range Hosts {
			ExtractNetwork(
				Hosts[i],
				OptionCmd.Silent,
				OptionCmd.Onlydomains,
				OptionCmd.Onlynetworks)
		}
	}

	if len(Networks) > 0 && !OptionCmd.Onlynetworks {
		for i := range Networks {
			if score, err := strconv.ParseUint(OptionCmd.VtscoreValue, 10, 64); err == nil {
				ExtractDomains(Networks[i], OptionCmd.Silent, OptionCmd.Vtscore, score)
			} else {
				gologger.Fatal().Msg("Invalid parameter value for vt-score")
			}
		}
	}
}
