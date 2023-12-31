<p align="center">
  <img src="assets/logo.png">
</p>

<h1 align="center">HEDnsExtractor</h1>
<p align="center">
  A suite for hunting suspicious targets, expose domains and phishing discovery
</p>
<p align="center">
  <a href="https://go.dev/">
    <img src="https://img.shields.io/github/go-mod/go-version/HuntDownProject/hednsextractor">
  </a>
    <a href="https://opensource.org">
    <img src="https://img.shields.io/badge/Open%20Source-%E2%9D%A4-brightgreen.svg">
  </a>
</p>

## Features

* Implementing workflows with yaml 🔥
* Adds support to work with multiples domains as target 🔥
* Regex support 🥷
* VirusTotal Integration
* Adds support to work with IPv6 filters 🔥
* Extract networks based on IP/Domain
* Extract domains from networks.
  
# Workflows

## Installation

```
go install -v github.com/HuntDownProject/hednsextractor/cmd/hednsextractor@latest
```

## Usage

```bash
hednsextractor -h
```

```
HEDnsExtractor - Raw html extractor from Hurricane Electric portal!

Usage:
  hednsextractor [flags]

Flags:
CONFIGURATION:
   -config string  flag config file (default "/home/hunter/.config/hednsextractor/config.yaml")

VIRUSTOTAL:
   -vt                 show Virustotal score
   -vt-api-key string  Virustotal API Key
   -vt-score string    Minimum Virustotal score to show (default "0")

OTHER OPTIONS:
   -only-domains     show only domains
   -only-networks    show only networks
   -workflow string  Workflow config
   -target string    IP Address or Network to query
   -silent           show silent output
   -verbose          show verbose output
```

## Running

Getting the IP Addresses used for hackerone.com, and enumerating only the networks.

```bash
nslookup hackerone.com | awk '/Address: / {print $2}' | hednsextractor -silent -only-networks

[INF] [104.16.99.52] 104.16.0.0/12
[INF] [104.16.99.52] 104.16.96.0/20
```

Getting the IP Addresses used for hackerone.com, and enumerating only the domains (using tail to show the first 10 results).

```bash
nslookup hackerone.com | awk '/Address: / {print $2}' | hednsextractor -silent -only-domains | tail -n 10

herllus.com
hezzy.store
hilariostore.com
hiperdrop.com
hippratas.online
hitsstory.com
hobbyshop.site
holyangelstore.com
holzfallerstore.fun
homedescontoo.com
```

### Running with Virustotal

Edit the config file and add the Virustotal API Key

```bash
cat $HOME/.config/hednsextractor/config.yaml 
```

```ini
# hednsextractor config file
# generated by https://github.com/projectdiscovery/goflags

# show only domains
#only-domains: false

# show only networks
#only-networks: false

# show virustotal score
#vt: false

# minimum virustotal score to show
#vt-score: 0

# ip address or network to query
#target: 

# show silent output
#silent: false

# show verbose output
#verbose: false

# virustotal api key
vt-api-key: Your API Key goes here
```

So, run the `hednsextractor` with `-vt` parameter.

```bash 
nslookup hackerone.com | awk '/Address: / {print $2}' | hednsextractor -only-domains -vt             
```

And the output will be as below
```
╭╮╱╭┳━━━┳━━━╮╱╱╱╱╱╭━━━╮╱╱╭╮╱╱╱╱╱╱╱╱╭╮
┃┃╱┃┃╭━━┻╮╭╮┃╱╱╱╱╱┃╭━━╯╱╭╯╰╮╱╱╱╱╱╱╭╯╰╮
┃╰━╯┃╰━━╮┃┃┃┣━╮╭━━┫╰━━┳╮┣╮╭╋━┳━━┳━┻╮╭╋━━┳━╮
┃╭━╮┃╭━━╯┃┃┃┃╭╮┫━━┫╭━━┻╋╋┫┃┃╭┫╭╮┃╭━┫┃┃╭╮┃╭╯
┃┃╱┃┃╰━━┳╯╰╯┃┃┃┣━━┃╰━━┳╋╋┫╰┫┃┃╭╮┃╰━┫╰┫╰╯┃┃
╰╯╱╰┻━━━┻━━━┻╯╰┻━━┻━━━┻╯╰┻━┻╯╰╯╰┻━━┻━┻━━┻╯

[INF] Current hednsextractor version v1.0.0
[INF] [104.16.0.0/12] domain: ohst.ltd VT Score: 0
[INF] [104.16.0.0/12] domain: jxcraft.net VT Score: 0
[INF] [104.16.0.0/12] domain: teatimegm.com VT Score: 2
[INF] [104.16.0.0/12] domain: debugcheat.com VT Score: 0
```

