package api

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
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/unrolled/secure"
	"github.com/urfave/negroni"
)

func Serve(ctx context.Context) error {
	if e != nil {
		return e
	}

	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return err
	}
	defer ln.Close()

	tlsCfg, err := tlsConfig()
	if err != nil {
		return err
	}

	r.Use(mux.CORSMethodMiddleware(r))

	n := negroni.Classic() // Not the best, but decent enough for a reference implementation.

	// A few easy security wins
	secureMiddleware := secure.New(secure.Options{
		SSLRedirect:           true,
		STSSeconds:            31536000,
		STSIncludeSubdomains:  true,
		STSPreload:            true,
		FrameDeny:             true,
		ContentTypeNosniff:    true,
		BrowserXssFilter:      true,
		ContentSecurityPolicy: "default-src 'self'; script-src $NONCE",
	})
	n.Use(negroni.HandlerFunc(secureMiddleware.HandlerFuncWithNext))

	n.Use(cors.Default())

	n.UseHandler(r)

	srv := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      n,
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
	case http.ErrServerClosed:
	case context.Canceled:
	case context.DeadlineExceeded:
		if err := srv.Close(); err != nil {
			return err
		}
	default:
		if err := srv.Close(); err != nil {
			return err
		}
	}

	if err := <-ch; err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// A basic tuned TLS config.
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

// A self-signed certificate.
func tlsCert() (tls.Certificate, error) {
	var (
		cert tls.Certificate
		priv interface{}
		err  error
	)
	priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
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

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}
