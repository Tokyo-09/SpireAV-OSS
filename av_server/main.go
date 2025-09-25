package main

import (
	"crypto/tls"
	"log"
	"net/http"
)

var (
	CertFilePath = "/home/user/server-cert.pem"
	KeyFilePath  = "/home/user/server-key.pem"
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
		Addr:      ":8080",
		Handler:   http.HandlerFunc(httpRequestHandler),
		TLSConfig: tlsConfig,
	}
	defer server.Close()
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func httpRequestHandler(w http.ResponseWriter, req *http.Request) {
	w.Write([]byte("Hello,World!\n"))
}
