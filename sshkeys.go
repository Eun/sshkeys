package sshkeys

import (
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

func GetKeys(host string, timeout time.Duration) ([]ssh.PublicKey, error) {
	// from ssh.supportedHostKeyAlgos
	supportedHostKeyAlgos := []string{
		ssh.CertAlgoRSAv01, ssh.CertAlgoDSAv01, ssh.CertAlgoECDSA256v01,
		ssh.CertAlgoECDSA384v01, ssh.CertAlgoECDSA521v01, ssh.CertAlgoED25519v01,
		ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
		ssh.KeyAlgoRSA, ssh.KeyAlgoDSA,
		ssh.KeyAlgoED25519,
	}

	type result struct {
		Key   ssh.PublicKey
		Error error
	}

	var wg sync.WaitGroup

	results := make(chan result, len(supportedHostKeyAlgos))

	for _, algo := range supportedHostKeyAlgos {
		wg.Add(1)
		go func(algo string) {
			defer wg.Done()
			key, err := getPublicKey(host, algo, timeout)
			results <- result{key, err}
		}(algo)
	}
	wg.Wait()

	var keys []ssh.PublicKey
	for range supportedHostKeyAlgos {
		result := <-results
		if result.Error != nil {
			return nil, result.Error
		}
		if result.Key != nil {
			keys = append(keys, result.Key)
		}
	}
	return keys, nil
}

func GetVersion(host string, timeout time.Duration) (string, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", host)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	bytes := make([]byte, 255)
	n, err := conn.Read(bytes)
	if err != nil {
		return "", err
	}

	for i := 0; i < n; i++ {
		if bytes[i] < 32 {
			return string(bytes[:i]), nil
		}
	}

	return "unknown", nil

}

func getPublicKey(host, algo string, timeout time.Duration) (key ssh.PublicKey, err error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", host)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	config := ssh.ClientConfig{
		HostKeyAlgorithms: []string{algo},
		HostKeyCallback:   hostKeyCallback(&key),
	}
	sshconn, _, _, err := ssh.NewClientConn(conn, host, &config)
	if err == nil {
		sshconn.Close()
	}
	return key, nil
}

func hostKeyCallback(publicKey *ssh.PublicKey) func(hostname string, remote net.Addr, key ssh.PublicKey) error {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		*publicKey = key
		return nil
	}
}
