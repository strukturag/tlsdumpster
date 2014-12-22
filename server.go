/*
tlsdumpster - Tntercepting web server to help with analyzation of
TLS encrypted HTTP traffic.

Copyright (c) 2014, struktur AG
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the <organization> nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/kr/pretty"
	"log"
	"net/http"
	"time"
)

var listenAddress string
var certFile string
var keyFile string

func init() {
	flag.StringVar(&listenAddress, "l", "127.0.0.1:8443", "Listen address.")
	flag.StringVar(&certFile, "cert", "", "Certificate file.")
	flag.StringVar(&keyFile, "key", "", "Key file.")
}

func makeDefaultCipherSuites() []uint16 {
	// Default cipher suites - no RC4.
	return []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	}
}

func handler(w http.ResponseWriter, r *http.Request) {

	fmt.Printf("%s host   : %s\n", r.RemoteAddr, r.Host)
	fmt.Printf("%s uri    : %s\n", r.RemoteAddr, r.RequestURI)
	fmt.Printf("%s method : %s\n", r.RemoteAddr, r.Method)
	fmt.Printf("%s header : %# v\n", r.RemoteAddr, pretty.Formatter(r.Header))

	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)
	fmt.Printf("%s body : %# v\n", r.RemoteAddr, pretty.Formatter(buf.String()))

	http.Error(w, "Nothing here", http.StatusInternalServerError)

}

func main() {

	var err error

	flag.Parse()

	if certFile == "" {
		log.Fatal("No certificate file given")
	}
	if keyFile == "" {
		log.Fatal("No key file given")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)

	certificates := make([]tls.Certificate, 1)
	certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatal("Failed to parse certificate: ", err)
	}

	config := &tls.Config{
		Rand: rand.Reader,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS10,
		MaxVersion:               tls.VersionTLS12,
		CipherSuites:             makeDefaultCipherSuites(),
		Certificates:             certificates,
	}
	config.BuildNameToCertificate()

	s := &http.Server{
		Addr:           listenAddress,
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
		TLSConfig:      config,
	}

	log.Printf("Listening on %s\n", listenAddress)
	err = s.ListenAndServeTLS(certFile, keyFile)
	if err != nil {
		log.Fatal("Failed: ", err)
	}

}
