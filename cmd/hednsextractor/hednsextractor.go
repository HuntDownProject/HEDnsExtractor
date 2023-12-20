package main

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/HuntDownProject/hednsextractor/utils"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

var (
	outputs []string
)

func main() {

	utils.ParseStdin()

	flagSet := goflags.NewFlagSet()
	flagSet.Marshal = true
	flagSet.SetDescription("HEDnsExtractor - A suite for hunting suspicious targets, expose domains and phishing discovery!")
	flagSet.BoolVar(&utils.OptionCmd.Onlydomains, "only-domains", false, "show only domains")
	flagSet.BoolVar(&utils.OptionCmd.Onlynetworks, "only-networks", false, "show only networks")
	flagSet.StringVar(&utils.OptionCmd.Workflow, "workflow", "", "Workflow config")
	flagSet.StringVar(&utils.OptionCmd.Target, "target", "", "IP Address or Network to query")
	flagSet.BoolVar(&utils.OptionCmd.Silent, "silent", false, "show silent output")
	flagSet.BoolVar(&utils.OptionCmd.Verbose, "verbose", false, "show verbose output")

	flagSet.CreateGroup("configuration", "Configuration",
		flagSet.StringVar(&utils.OptionCmd.Config, "config", utils.DefaultConfigLocation, "flag config file"),
	)

	flagSet.CreateGroup("config", "Virustotal",
		flagSet.BoolVar(&utils.OptionCmd.Vtscore, "vt", false, "show Virustotal score"),
		flagSet.StringVar(&utils.OptionCmd.VtApiKey, "vt-api-key", "", "Virustotal API Key"),
		flagSet.StringVar(&utils.OptionCmd.VtscoreValue, "vt-score", "0", "Minimum Virustotal score to show"),
	)

	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msgf("Could not parse flags: %s\n", err)
	}

	if utils.OptionCmd.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	} else if utils.OptionCmd.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	} else {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	}

	if utils.OptionCmd.Vtscore && utils.OptionCmd.VtApiKey == "" {
		gologger.Fatal().Msgf("A Virustotal API Key is needed in config file: %s\n", utils.DefaultConfigLocation)
	}

	// Show Banner
	utils.ShowBanner()

	// read the targets from yaml
	var c utils.Conf
	if utils.OptionCmd.Workflow != "" {
		c.GetConf(utils.OptionCmd.Workflow)

		for i := range c.Domains {
			utils.IdentifyTarget(c.Domains[i])
		}

		for i := range c.Ipaddrs {
			utils.IdentifyTarget(c.Ipaddrs[i])
		}

		for i := range c.Networks {
			utils.IdentifyTarget(c.Networks[i])
		}
	}

	// Look into target parameter to grab the IPv4s and Networks
	if utils.OptionCmd.Target != "" {
		gologger.Verbose().Msgf("Identifying networks for %s", utils.OptionCmd.Target)
		utils.IdentifyTarget(utils.OptionCmd.Target)
	}

	utils.RunCrawler()

	if utils.OptionCmd.Vtscore && !utils.OptionCmd.Silent {
		gologger.Info().Msgf("Filtering with Virustotal with a mininum score %s", utils.OptionCmd.VtscoreValue)
	}

	for _, result := range utils.Results {
		var bMatchedPTR = false
		var bMatchedDomain = false

		if c.Regex != "" {
			var re = regexp.MustCompile(c.Regex)
			bMatchedDomain = re.MatchString(result.Domain)
			bMatchedPTR = re.MatchString(result.PTR)
		} else {
			bMatchedPTR = true
			bMatchedDomain = true
		}

		if !bMatchedDomain && !bMatchedPTR {
			continue
		}

		if utils.OptionCmd.Vtscore {
			result.VtScore = utils.GetVtReport(result.Domain)
			if score, err := strconv.ParseUint(utils.OptionCmd.VtscoreValue, 10, 64); err == nil {
				if result.VtScore < score {
					continue
				}
			} else {
				gologger.Fatal().Msg("Invalid parameter value for vt-score")
			}
		}

		var output = prepareOutput(result, bMatchedDomain, bMatchedPTR)
		if !utils.Contains(outputs, output) {
			outputs = append(outputs, output)
		}
	}

	for _, output := range outputs {
		if utils.OptionCmd.Silent {
			gologger.Silent().Msgf(output)
		} else {
			gologger.Info().Msgf(output)
		}
	}
}

func prepareOutput(result utils.Result, bMatchedDomain bool, bMatchedPTR bool) string {
	var output = ""

	if bMatchedDomain && result.Domain != "" {
		if utils.OptionCmd.Silent {
			output = fmt.Sprintf("%s\n", result.Domain)
		} else {
			output = fmt.Sprintf("[%s] domain: %s", result.IPAddr, result.Domain)
		}
	}

	if bMatchedPTR && result.PTR != "" {
		if utils.OptionCmd.Silent {
			output = fmt.Sprintf("%s\n", result.PTR)
		} else {
			output = fmt.Sprintf("[%s] PTR: %s", result.IPAddr, result.PTR)
		}
	}

	if !utils.OptionCmd.Silent {
		if utils.OptionCmd.Vtscore {
			output = fmt.Sprintf("%s VT Score: %d", output, result.VtScore)
		}
	}
	return output
}
