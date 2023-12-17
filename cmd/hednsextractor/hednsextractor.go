package main

import (
	"github.com/HuntDownProject/hednsextractor/utils"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

func main() {

	utils.ParseStdin()

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("HEDnsExtractor - Raw html extractor from Hurricane Electric portal!")
	flagSet.BoolVar(&utils.OptionCmd.Onlydomains, "only-domains", false, "show only domains")
	flagSet.BoolVar(&utils.OptionCmd.Onlynetworks, "only-networks", false, "show only networks")
	flagSet.BoolVar(&utils.OptionCmd.Vtscore, "vt", false, "show Virustotal score")
	flagSet.StringVar(&utils.OptionCmd.VtscoreValue, "vt-score", "0", "Minimum Virustotal score to show")
	flagSet.StringVar(&utils.OptionCmd.Target, "target", "", "IP Address or Network to query")
	flagSet.BoolVar(&utils.OptionCmd.Silent, "silent", false, "show silent output")
	flagSet.BoolVar(&utils.OptionCmd.Verbose, "verbose", false, "show verbose output")

	// Group example
	flagSet.CreateGroup("config", "Configuration",
		flagSet.StringVar(&utils.OptionCmd.VtApiKey, "vt-api-key", "", "Virustotal API Key"),
	)

	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msgf("Could not parse flags: %s\n", err)
	}

	if utils.OptionCmd.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	} else {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	}

	// Show Banner
	utils.ShowBanner(utils.OptionCmd.Silent)

	// Look into target parameter to grab the IPv4s and Networks
	if utils.OptionCmd.Target != "" {
		utils.IdentifyTarget(utils.OptionCmd.Target)
	}

	utils.RunCrawler()
}
