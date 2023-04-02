package sshkeys_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

func generatePrivateRSAKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, fmt.Errorf("unable to generate key: %w", err)
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, fmt.Errorf("unable to validate key: %w", err)
	}
	return privateKey, nil
}

func createRSAKey(bitSize int) (ssh.Signer, error) {
	pk, err := generatePrivateRSAKey(bitSize)
	if err != nil {
		return nil, fmt.Errorf("unable to create private key: %w", err)
	}
	privateKey, err := ssh.ParsePrivateKey(pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(pk),
	}))
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key: %w", err)
	}
	return privateKey, nil
}

func generatePrivateECDSAKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("unable to generate key: %w", err)
	}
	return privateKey, nil
}

func createECDSAKey(curve elliptic.Curve) (ssh.Signer, error) {
	pk, err := generatePrivateECDSAKey(curve)
	if err != nil {
		return nil, fmt.Errorf("unable to create private key: %w", err)
	}
	buf, err := x509.MarshalECPrivateKey(pk)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal private key: %w", err)
	}
	privateKey, err := ssh.ParsePrivateKey(pem.EncodeToMemory(&pem.Block{
		Type:    "EC PRIVATE KEY",
		Headers: nil,
		Bytes:   buf,
	}))
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key: %w", err)
	}
	return privateKey, nil
}
