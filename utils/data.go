package utils

import (
	"log"
	"os"
	"path/filepath"

	"github.com/projectdiscovery/gologger"
	folderutil "github.com/projectdiscovery/utils/folder"
	"gopkg.in/yaml.v2"
)

const urlBase = "https://bgp.he.net/"

type Conf struct {
	Domains  []string `yaml:"domains"`
	Ipaddrs  []string `yaml:"ipaddrs"`
	Networks []string `yaml:"networks"`
	Regex    string   `yaml:"regex"`
}

type Result struct {
	IPAddr  string
	PTR     string
	Domain  string
	VtScore uint64
}

var (
	configDir             = folderutil.AppConfigDirOrDefault(".", "hednsextractor")
	DefaultConfigLocation = filepath.Join(configDir, "config.yaml")

	Hosts    []string
	Networks []string
	Domains  []string
)

var Results = make(map[string]Result)

func (c *Conf) GetConf(filename string) *Conf {
	yamlFile, err := os.ReadFile(filename)
	if err != nil {
		gologger.Fatal().Msgf("Could not %s\n", err)
	}

	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}
	return c
}
