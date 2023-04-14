package sshkeys_test

import (
	"context"
	"crypto/elliptic"
	"errors"
	"log"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/Eun/sshkeys"
	"github.com/gliderlabs/ssh"
	"github.com/stretchr/testify/require"
	xssh "golang.org/x/crypto/ssh"
)

func TestGetVersion(t *testing.T) {
	t.Parallel()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()

	expectedVersion := strconv.FormatInt(time.Now().Unix(), 36)
	server := ssh.Server{
		ServerConfigCallback: func(ctx ssh.Context) *xssh.ServerConfig {
			return &xssh.ServerConfig{
				Config:                      xssh.Config{},
				NoClientAuth:                false,
				NoClientAuthCallback:        nil,
				MaxAuthTries:                0,
				PasswordCallback:            nil,
				PublicKeyCallback:           nil,
				KeyboardInteractiveCallback: nil,
				AuthLogCallback:             nil,
				ServerVersion:               expectedVersion,
				BannerCallback:              nil,
				GSSAPIWithMICConfig:         nil,
			}
		},
	}
	defer server.Close()
	go func() {
		if sshServerErr := server.Serve(l); sshServerErr != nil {
			if errors.Is(sshServerErr, ssh.ErrServerClosed) {
				return
			}
			log.Fatal(sshServerErr)
		}
	}()

	version, err := sshkeys.GetVersion(context.Background(), l.Addr().String())
	require.NoError(t, err)
	require.Equal(t, expectedVersion, version)
}

func TestGetKeys(t *testing.T) {
	t.Parallel()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()

	privateRSAKey, err := createRSAKey(2047)
	require.NoError(t, err)

	privateECKey, err := createECDSAKey(elliptic.P256())
	require.NoError(t, err)

	server := ssh.Server{
		HostSigners: []ssh.Signer{privateRSAKey, privateECKey},
	}
	defer server.Close()
	go func() {
		if sshServerErr := server.Serve(l); sshServerErr != nil {
			if errors.Is(sshServerErr, ssh.ErrServerClosed) {
				return
			}
			log.Fatal(sshServerErr)
		}
	}()

	keys, err := sshkeys.GetKeys(context.Background(), l.Addr().String(), 4, time.Minute, sshkeys.DefaultKeyAlgorithms()...)
	require.NoError(t, err)

	fingerprints := make(map[string]string)
	for k, v := range keys {
		fingerprints[k] = xssh.FingerprintSHA256(v)
	}

	require.Equal(t, map[string]string{
		xssh.KeyAlgoRSA:       xssh.FingerprintSHA256(privateRSAKey.PublicKey()),
		xssh.KeyAlgoRSASHA256: xssh.FingerprintSHA256(privateRSAKey.PublicKey()),
		xssh.KeyAlgoRSASHA512: xssh.FingerprintSHA256(privateRSAKey.PublicKey()),
		xssh.KeyAlgoECDSA256:  xssh.FingerprintSHA256(privateECKey.PublicKey()),
	}, fingerprints)
}
