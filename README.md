# sshkeys

Get all ssh public keys of a ssh server

### Installation

    go get -u github.com/Eun/sshkeys/cmd/sshkeys

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

