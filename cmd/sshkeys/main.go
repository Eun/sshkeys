package main

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"

	"golang.org/x/crypto/ssh"

	"github.com/Eun/sshkeys"
)

var formatOption string
var outputOption string
var timeoutOption string

const (
	authorized_keys = 1
	fingerprintMD5  = 2
	fingerprintSHA1 = 3
)

const (
	outputConsole = 0
	outputJSON    = 1
)

func init() {
	flag.StringVar(&formatOption, "format", "authorized_keys", "")
	flag.StringVar(&formatOption, "f", "authorized_keys", "")
	flag.StringVar(&outputOption, "output", "", "")
	flag.StringVar(&outputOption, "o", "", "")
	flag.StringVar(&timeoutOption, "timeout", "60s", "")
	flag.StringVar(&timeoutOption, "t", "60s", "")

}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options] <host>\n", filepath.Base(os.Args[0]))
	fmt.Fprintln(os.Stderr, "Options:")
	fmt.Fprintln(os.Stderr, "    -format=authorized_keys       Format to print the public keys, valid formats are: fingerprint, fingerprint-sha1, sha1, fingerprint-legacy, fingerprint-md5, md5, authorized_keys, authorizedkeys, authorized")
	fmt.Fprintln(os.Stderr, "    -output=console               Output format, valid formats are: console, json")
	fmt.Fprintln(os.Stderr, "    -timeout=60s                  Connection timeout")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "sshkeys 1.12 https://github.com/Eun/sshkeys")
}

func main() {

	flag.Usage = usage
	flag.Parse()
	args := flag.Args()
	if len(args) <= 0 {
		usage()
		os.Exit(1)
	}

	host := strings.TrimSpace(args[0])

	format := parseFormat(formatOption)
	output := parseOutput(outputOption)

	timeout, err := time.ParseDuration(timeoutOption)
	if err != nil {
		fmt.Fprintf(os.Stderr, "'%s' is not a duration\n", timeoutOption)
		os.Exit(1)
	}

	internalHost := host

	if !govalidator.IsDialString(host) {
		if !govalidator.IsHost(host) {

			switch output {
			case outputJSON:
				json.NewEncoder(os.Stdout).Encode(struct {
					Host  string
					Error string
				}{host, fmt.Sprintf("'%s' is not a valid hostname", host)})
			default:
				fmt.Fprintf(os.Stderr, "'%s' is not a valid hostname\n", host)
			}
			os.Exit(1)
		}
		internalHost = net.JoinHostPort(internalHost, "22")
	}

	keys, err := sshkeys.GetKeys(internalHost, timeout)

	if err != nil {
		switch output {
		case outputJSON:
			json.NewEncoder(os.Stdout).Encode(struct {
				Host  string
				Error string
			}{host, err.Error()})
		default:
			fmt.Println(err)
		}
		os.Exit(1)
	}

	var printableKeys []string

	for i := 0; i < len(keys); i++ {
		printableKeys = append(printableKeys, keyToString(keys[i], format))
	}

	switch output {
	case outputJSON:
		json.NewEncoder(os.Stdout).Encode(struct {
			Host       string
			PublicKeys []string
		}{host, printableKeys})
	default:
		for i := 0; i < len(printableKeys); i++ {
			fmt.Println(printableKeys[i])
		}
	}
}

func sumToString(sum []byte) (s string) {
	for i := 0; i < len(sum); i++ {
		s += fmt.Sprintf("%02x", sum[i])
		if i < len(sum)-1 {
			s += ":"
		}
	}
	return s
}

func keyToString(key ssh.PublicKey, format int) string {
	switch format {
	case fingerprintMD5:
		sum := md5.Sum(key.Marshal())
		return fmt.Sprintf("%s", sumToString(sum[:]))
	case fingerprintSHA1:
		sum := sha1.Sum(key.Marshal())
		return fmt.Sprintf("%s", sumToString(sum[:]))
	case authorized_keys:
		fallthrough
	default:
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	}
}

func parseFormat(format string) int {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "fingerprint":
		fallthrough
	case "sha1":
		fallthrough
	case "fingerprint-sha1":
		return fingerprintSHA1

	case "fingerprint-legacy":
		fallthrough
	case "md5":
		fallthrough
	case "fingerprint-md5":
		return fingerprintMD5

	case "authorized_keys":
		fallthrough
	case "authorizedkeys":
		fallthrough
	case "authorized":
		fallthrough
	case "4716":
		fallthrough
	case "rfc-4716":
		fallthrough
	case "rfc4716":
		fallthrough
	default:
		return authorized_keys
	}
}

func parseOutput(output string) int {
	switch strings.ToLower(strings.TrimSpace(output)) {
	case "json":
		return outputJSON
	case "console":
		fallthrough
	default:
		return outputConsole
	}
}
