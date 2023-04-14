# sshkeys
[![Actions Status](https://github.com/Eun/sshkeys/workflows/push/badge.svg)](https://github.com/Eun/sshkeys/actions)
[![Coverage Status](https://coveralls.io/repos/github/Eun/sshkeys/badge.svg?branch=master)](https://coveralls.io/github/Eun/sshkeys?branch=master)
[![PkgGoDev](https://img.shields.io/badge/pkg.go.dev-reference-blue)](https://pkg.go.dev/github.com/Eun/sshkeys)
[![go-report](https://goreportcard.com/badge/github.com/Eun/sshkeys)](https://goreportcard.com/report/github.com/Eun/sshkeys)
---
Get all ssh public keys of an ssh server.

## Installation

### Docker
```shell
$ docker run --rm -ti ghcr.io/eun/sshkeys:latest -algorithm=sha256 -encoding=base64 github.com
```

### Prebuild
Download in the [Releases](https://github.com/Eun/sshkeys/releases) section.

### go
```shell
$ go install github.com/Eun/sshkeys/cmd/sshkeys
```

## Usage
```shell
Usage: sshkeys [options] <host>
Options:
    -a authorized_keys
    -algorithm=authorized_keys
       Algorithm to hash the public keys, valid algorithms are: sha1, sha256, md5, authorized_keys

    -e=
    -encoding=
       Encoding to encode the hashed keys, valid encodings are: hex, base32, base64 (only used for algorithms sha1, sha256 and md5)

    -o=console
    -output=console
       Output format, valid formats are: console, json

    -c=4
    -concurrent=4
       Concurrent workers

    -t=60s
    -timeout=60s
       Connection timeout
```

### Examples
```shell
$ sshkeys example.com
$ sshkeys -algorithm=sha256 -encoding=base64 -output=json github.com:22
```

## Build History
[![Build history](https://buildstats.info/github/chart/Eun/sshkeys?branch=master)](https://github.com/Eun/go-bin-template/actions)