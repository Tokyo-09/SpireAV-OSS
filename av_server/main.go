package main

import (
	"crypto/tls"
	"log"
	"net/http"
)

var (
	CertFilePath = "./server.ecdsa.crt"
	KeyFilePath  = "./server.ecdsa.key"
)

func main() {
	serverTLSCert, err := tls.LoadX509KeyPair(CertFilePath, KeyFilePath)
	if err != nil {
		log.Fatalf("Error loading certificate and key file: %v", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
	}
	server := http.Server{
		Addr:      ":8081",
		Handler:   http.HandlerFunc(httpRequestHandler),
		TLSConfig: tlsConfig,
	}
	defer server.Close()
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func httpRequestHandler(w http.ResponseWriter, req *http.Request) {
	w.Write([]byte("Hello,World!\n"))
}
