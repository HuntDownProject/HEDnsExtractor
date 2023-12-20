package utils

type options struct {
	Silent       bool
	Verbose      bool
	Onlydomains  bool
	Onlynetworks bool
	Workflow     string
	Vtscore      bool
	VtscoreValue string
	VtApiKey     string
	Target       string
	Domain       string
	Config       string
}

var OptionCmd = &options{}
