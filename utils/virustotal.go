package utils

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/tidwall/gjson"
	"net/http/httputil"
)

func GetVtReport(domain string) uint64 {
	urlBase := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", domain)

	request, err := retryablehttp.NewRequest("GET", urlBase, nil)
	if err != nil {
		gologger.Fatal().Msgf("err: %v", err)
	}
	request.Header.Set("x-apikey", OptionCmd.VtApiKey)

	opts := retryablehttp.DefaultOptionsSpraying
	client := retryablehttp.NewClient(opts)
	response, err := client.Do(request)
	if err != nil {
		panic(err)
	}

	bin, err := httputil.DumpResponse(response, true)
	if err != nil {
		panic(err)
	}
	str := string(bin)

	malicious := gjson.Get(str, "data.attributes.last_analysis_stats.malicious")
	suspicious := gjson.Get(str, "data.attributes.last_analysis_stats.suspicious")
	vtScore := malicious.Uint() + suspicious.Uint()
	return vtScore
}
