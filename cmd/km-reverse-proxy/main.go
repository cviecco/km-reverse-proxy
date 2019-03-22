package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/cviecco/km-reverse-proxy/authnHandler"
)

var (
	configFilename = flag.String("config", "config.yml", "Configuration filename")
)

func main() {
	flag.Parse()
	staticConfig, err := LoadVerifyConfigFile(*configFilename)
	if err != nil {
		log.Fatalf("Cannot load Configuration: %s\n", err)
	}

	//log.Printf("%+v", staticConfig)

	origin, err := url.Parse(staticConfig.Base.ReverseProxyURL)
	if err != nil {
		panic(err)
	}

	director := func(req *http.Request) {
		req.Header.Add("X-Forwarded-Host", req.Host)
		req.Header.Add("X-Origin-Host", origin.Host)
		req.URL.Scheme = origin.Scheme
		req.URL.Host = origin.Host
	}

	proxy := &httputil.ReverseProxy{Director: director}

	authZ := NewAuthZHandler(proxy, staticConfig.Base.PathConfigLocation, &staticConfig.Ldap)
	err = authZ.(*AuthZHandler).LoadConfig()
	if err != nil {
		panic(err)
	}

	authN := authnHandler.NewAuthNHandler(authZ, staticConfig.OpenID, staticConfig.Base.SharedSecrets)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		authN.ServeHTTP(w, r)
	})

	var clientCACertPool *x509.CertPool
	if len(staticConfig.Base.ClientCAFilename) > 0 {
		clientCACertPool = x509.NewCertPool()
		caCert, err := ioutil.ReadFile(staticConfig.Base.ClientCAFilename)
		if err != nil {
			log.Fatalf("cannot read clientCA file err=%s", err)
		}
		clientCACertPool.AppendCertsFromPEM(caCert)
	}
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  clientCACertPool,
	}
	addr := fmt.Sprintf(":%d", staticConfig.Base.ServicePort)
	server := &http.Server{
		Addr: addr,
		//Handler:      NewLoggingHandler(http.DefaultServeMux, l),
		TLSConfig:    tlsConfig,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	log.Fatal(server.ListenAndServeTLS(staticConfig.Base.TLSCertFilename, staticConfig.Base.TLSKeyFilename))
	//log.Fatal(http.ListenAndServeTLS(addr, staticConfig.Base.TLSCertFilename, staticConfig.Base.TLSKeyFilename, nil))
}
