package sshkeys

import (
	"context"
	"crypto/md5"  //nolint: gosec // allow weak cryptographic primitive
	"crypto/sha1" //nolint: gosec // allow weak cryptographic primitive
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

// DefaultKeyAlgorithms returns the default ssh key algorithms.
func DefaultKeyAlgorithms() []string {
	return []string{
		ssh.KeyAlgoRSA,
		ssh.KeyAlgoDSA,
		ssh.KeyAlgoECDSA256,
		ssh.KeyAlgoSKECDSA256,
		ssh.KeyAlgoECDSA384,
		ssh.KeyAlgoECDSA521,
		ssh.KeyAlgoED25519,
		ssh.KeyAlgoSKED25519,
		ssh.KeyAlgoRSASHA256,
		ssh.KeyAlgoRSASHA512,
		ssh.CertAlgoRSAv01,
		ssh.CertAlgoDSAv01,
		ssh.CertAlgoECDSA256v01,
		ssh.CertAlgoECDSA384v01,
		ssh.CertAlgoECDSA521v01,
		ssh.CertAlgoSKECDSA256v01,
		ssh.CertAlgoED25519v01,
		ssh.CertAlgoSKED25519v01,
		ssh.CertAlgoRSASHA256v01,
		ssh.CertAlgoRSASHA512v01,
	}
}

// GetKeys gets the public keys for a host.
// Specify the amount of concurrentWorkers and the algorithms that should be used to fetch the keys.
// If unsure use DefaultKeyAlgorithms.
func GetKeys(
	ctx context.Context,
	host string,
	concurrentWorkers int,
	timeout time.Duration,
	algorithms ...string,
) (map[string]ssh.PublicKey, error) {
	if len(algorithms) == 0 {
		algorithms = DefaultKeyAlgorithms()
	}

	if concurrentWorkers < 0 {
		concurrentWorkers = 1
	}

	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	algoChan := make(chan string, len(algorithms))
	for _, algo := range algorithms {
		algoChan <- algo
	}

	resultChan := make(chan workerResult, len(algorithms))

	for i := 0; i < concurrentWorkers; i++ {
		go worker(workerCtx, host, timeout, algoChan, resultChan)
	}

	keys := make(map[string]ssh.PublicKey)
	for range algorithms {
		result := <-resultChan
		if result.err != nil {
			return nil, result.err
		}
		if result.key != nil {
			keys[result.algo] = result.key
		}
	}
	return keys, nil
}

type workerResult struct {
	algo string
	key  ssh.PublicKey
	err  error
}

func worker(ctx context.Context, host string, timeout time.Duration, algoChan chan string, resultChan chan workerResult) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return
		case algo := <-algoChan:
			key, err := getPublicKey(ctx, host, algo)
			resultChan <- workerResult{algo, key, err}
		}
	}
}

func getPublicKey(ctx context.Context, host, algo string) (key ssh.PublicKey, err error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	id := uuid.NewString()
	config := ssh.ClientConfig{
		Auth:              nil,
		HostKeyAlgorithms: []string{algo},
		HostKeyCallback:   hostKeyCallback(id, &key),
	}
	ch := make(chan error)
	go func() {
		sshconn, _, _, err := ssh.NewClientConn(conn, host, &config)
		if err != nil {
			if strings.Contains(err.Error(), "no common algorithm for host key") {
				ch <- nil
				return
			}
			if strings.Contains(err.Error(), "got hostkey for "+id) {
				ch <- nil
				return
			}
			ch <- err
			return
		}
		_ = sshconn.Close()
		ch <- errors.New("an session was established without exchanging keys")
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-ch:
		return key, err
	}
}

type hostKeyCallbackError struct {
	id string
}

func (a *hostKeyCallbackError) Error() string {
	return "got hostkey for " + a.id
}

func hostKeyCallback(id string, key *ssh.PublicKey) func(string, net.Addr, ssh.PublicKey) error { //nolint: gocritic,lll // allow passing key via ref
	return func(_ string, _ net.Addr, k ssh.PublicKey) error {
		*key = k
		return &hostKeyCallbackError{
			id: id,
		}
	}
}

// GetVersion returns the ssh version of the host.
func GetVersion(ctx context.Context, host string) (string, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	type result struct {
		version string
		err     error
	}
	const maxSize = 255
	const eoh = 32
	ch := make(chan result)
	go func() {
		var n int
		bytes := make([]byte, maxSize)
		n, err = conn.Read(bytes)
		if err != nil {
			ch <- result{
				version: "",
				err:     err,
			}
			return
		}

		for i := 0; i < n; i++ {
			if bytes[i] < eoh {
				ch <- result{
					version: string(bytes[:i]),
					err:     nil,
				}
				return
			}
		}
		ch <- result{
			version: "unknown",
			err:     nil,
		}
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case r := <-ch:
		return r.version, r.err
	}
}

// SumToHexString formats a sum in a aa:bb:cc:dd:ee:ff:... pattern.
func SumToHexString(sum []byte) string {
	var sb strings.Builder
	for i := 0; i < len(sum); i++ {
		fmt.Fprintf(&sb, "%02x", sum[i])
		if i < len(sum)-1 {
			sb.WriteRune(':')
		}
	}
	return sb.String()
}

type Encoding uint8

const (
	HexEncoding Encoding = iota
	Base32Encoding
	Base64Encoding
)

func encodeFingerprint(encoding Encoding, sum []byte) (string, error) {
	switch encoding {
	case HexEncoding:
		return SumToHexString(sum), nil
	case Base32Encoding:
		return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum), nil
	case Base64Encoding:
		return base64.RawStdEncoding.EncodeToString(sum), nil
	default:
		return "", errors.New("unknown encoding")
	}
}

// FingerprintMD5 creates the md5 fingerprint of the provided public key.
func FingerprintMD5(encoding Encoding, key ssh.PublicKey) (string, error) {
	sum := md5.Sum(key.Marshal()) //nolint: gosec // allow weak cryptographic primitive
	return encodeFingerprint(encoding, sum[:])
}

// FingerprintSHA1 creates the sha1 fingerprint of the provided public key.
func FingerprintSHA1(encoding Encoding, key ssh.PublicKey) (string, error) {
	sum := sha1.Sum(key.Marshal()) //nolint: gosec // allow weak cryptographic primitive
	return encodeFingerprint(encoding, sum[:])
}

// FingerprintSHA256 creates the sha256 fingerprint of the provided public key.
func FingerprintSHA256(encoding Encoding, key ssh.PublicKey) (string, error) {
	sum := sha256.Sum256(key.Marshal())
	return encodeFingerprint(encoding, sum[:])
}

// AuthorizedKey creates the authorized_key of the provided public key.
func AuthorizedKey(key ssh.PublicKey) (string, error) {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), nil
}
