package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// This is a reference implementation of an API that we'll
// implement in several other languages.
func main() {
	sig := make(chan os.Signal, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		time.Sleep(time.Second) // let everything start
		fmt.Fprintf(os.Stdout, "%s received\n", <-sig)
		cancel()
	}()

	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return err
	}
	defer ln.Close()

	tlsCfg, err := tlsConfig()
	if err != nil {
		return err
	}

	srv := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	srv.SetKeepAlivesEnabled(true)

	ch := make(chan error, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				switch t := p.(type) {
				case error:
					ch <- t
				default:
					ch <- fmt.Errorf("%v", p)
				}
			}
		}()
		ch <- srv.Serve(tls.NewListener(ln, tlsCfg))
	}()

	<-ctx.Done()

	newctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
	defer cancel()

	err = srv.Shutdown(newctx)
	switch err {
	case nil:
		return <-ch
	case http.ErrServerClosed:
		return <-ch
	case context.Canceled:
		return <-ch
	case context.DeadlineExceeded:
		if err := srv.Close(); err != nil {
			return err
		}
		return <-ch
	default:
		if err := srv.Close(); err != nil {
			return err
		}
		return <-ch
	}
}

func tlsConfig() (*tls.Config, error) {
	cert, err := tlsCert()
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}, nil
}

func tlsCert() (tls.Certificate, error) {
	var cert tls.Certificate
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return cert, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return cert, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.PublicKey, priv)
	if err != nil {
		return cert, err
	}

	var (
		certBuf bytes.Buffer
		keyBuf  bytes.Buffer
	)

	if err := pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return cert, err
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return cert, err
	}

	if err := pem.Encode(&keyBuf, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return cert, err
	}

	return tls.X509KeyPair(certBuf.Bytes(), keyBuf.Bytes())
}
