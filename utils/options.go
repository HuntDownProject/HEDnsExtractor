package utils

type options struct {
	Silent       bool
	Verbose      bool
	Onlydomains  bool
	Onlynetworks bool
	Vtscore      bool
	VtscoreValue string
	VtApiKey     string
	Target       string
}

var OptionCmd = &options{}
