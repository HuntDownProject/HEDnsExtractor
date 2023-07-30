<p align="center">
  <img src="assets/logo.png">
</p>

<h1 align="center">HEDnsExtractor</h1>
<p align="center">
  Raw html extractor from Hurricane Electric portal
</p>
<p align="center">
  <a href="https://python.org/">
    <img src="https://img.shields.io/github/go-mod/go-version/HuntDownProject/hednsextractor">
  </a>
    <a href="https://opensource.org">
    <img src="https://img.shields.io/badge/Open%20Source-%E2%9D%A4-brightgreen.svg">
  </a>
</p>

## Features

- Automatically identify IPAddr ou Networks through command line parameter or stdin
- Extract networks based on IPAddr.
- Extract domains from networks.

## Installation

```
$ go install -v github.com/HuntDownProject/hednsextractor/cmd/hednsextractor@latest
```

## Usage

```bash
usage -h
```

```
HEDnsExtractor - Raw html extractor from Hurricane Electric portal!

Usage:
  hednsextractor [flags]

Flags:
   -silent         show silent output
   -only-domains   show only domains
   -only-networks  show only networks
   -target string  IP Address or Network to query
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
