package sshkeys

import (
	"net"

	"golang.org/x/crypto/ssh"
)

func GetKeys(host string) ([]ssh.PublicKey, error) {
	// from ssh.supportedHostKeyAlgos
	supportedHostKeyAlgos := []string{
		ssh.CertAlgoRSAv01, ssh.CertAlgoDSAv01, ssh.CertAlgoECDSA256v01,
		ssh.CertAlgoECDSA384v01, ssh.CertAlgoECDSA521v01, ssh.CertAlgoED25519v01,
		ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
		ssh.KeyAlgoRSA, ssh.KeyAlgoDSA,
		ssh.KeyAlgoED25519,
	}

	var keys []ssh.PublicKey

	for _, algo := range supportedHostKeyAlgos {
		key, err := getPublicKey(host, algo)
		if err != nil {
			return nil, err
		}
		if key != nil {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func getPublicKey(host, algo string) (key ssh.PublicKey, err error) {
	d := net.Dialer{}
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
