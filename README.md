# sshkeys
[![Actions Status](https://github.com/Eun/sshkeys/workflows/push/badge.svg)](https://github.com/Eun/sshkeys/actions)
[![Coverage Status](https://coveralls.io/repos/github/Eun/sshkeys/badge.svg?branch=master)](https://coveralls.io/github/Eun/sshkeys?branch=master)
[![PkgGoDev](https://img.shields.io/badge/pkg.go.dev-reference-blue)](https://pkg.go.dev/github.com/Eun/sshkeys)
[![go-report](https://goreportcard.com/badge/github.com/Eun/sshkeys)](https://goreportcard.com/report/github.com/Eun/sshkeys)
---
Get all ssh public keys of an ssh server.

### Installation

    go install github.com/Eun/sshkeys/cmd/sshkeys

OR

Prebuild from [Releases](https://github.com/Eun/sshkeys/releases)

### Usage

    sshkeys [options] host

    Options:
        -format=authorized_keys       Format to print the public keys, valid formats are: fingerprint, fingerprint-sha1, sha1, fingerprint-legacy, fingerprint-md5, md5, authorized_keys, authorizedkeys, authorized
	    -output=console               Output format, valid formats are: console, json
        -timeout=60s                  Connection timeout

### Example

    sshkeys example.com
    sshkeys -format=fingerprint-md5 -output=json example.com:22


## Build History
[![Build history](https://buildstats.info/github/chart/Eun/sshkeys?branch=master)](https://github.com/Eun/go-bin-template/actions)