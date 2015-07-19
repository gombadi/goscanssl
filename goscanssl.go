package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

type goscanssl struct {
	host    string
	port    string
	cert    bool
	verbose bool
}

//
func main() {

	var config goscanssl

	flag.BoolVar(&config.cert, "c", false, "Display Certificate Info")
	flag.StringVar(&config.host, "h", "", "Remote host to test")
	flag.StringVar(&config.port, "p", "443", "Port to connect to. Default port: 443")
	flag.BoolVar(&config.verbose, "v", false, "Display verbose output")
	flag.Parse()

	if config.host == "" {
		fmt.Printf("Error: No host provided\n")
		os.Exit(1)
	}

	dialConfig := &net.Dialer{
		DualStack: true,
		Timeout:   (time.Second * 10),
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify:       true,
		PreferServerCipherSuites: true,
	}

	// loop over each protocol to test
	for _, p := range []uint16{tls.VersionSSL30, tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12} {

		tlsConfig.MinVersion = p
		tlsConfig.MaxVersion = p

		tlsconn, err := tls.DialWithDialer(dialConfig, "tcp", config.host+":"+config.port, tlsConfig)

		if err != nil {
			fmt.Printf("Failed - Protocol %s: Error: %s\n", getSSLVersion(p), err.Error())
			continue
		}

		cs := tlsconn.ConnectionState()

		if cs.HandshakeComplete == true {
			fmt.Printf("Connected - Protocol: %s\tCipher: %s\n", getSSLVersion(cs.Version), getCipher(cs.CipherSuite))
		} else {
			fmt.Printf("Error - TLS Handshake not completed. Unable to get connection details\n")
		}

		tlsconn.Close()

	}

	if config.cert == false {
		os.Exit(0)
	}

	tlscert, err := tls.Dial("tcp", config.host+":"+config.port, &tls.Config{InsecureSkipVerify: true})

	if err != nil {
		fmt.Printf("Unable to get Certificate details: %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Printf("\n\nCertificate Details from %s\n===================\n", tlscert.RemoteAddr().String())

	if err := tlscert.VerifyHostname(config.host); err != nil {
		fmt.Printf("Certificate Error: %v\n", err)
	} else {

		fmt.Printf("Certificate is valid for this domain\n")
	}

	cs := tlscert.ConnectionState()
	var first bool = true

	// reverse range over certs so root certificates shown first
	for i := len(cs.PeerCertificates) - 1; i >= 0; i-- {
		cert := cs.PeerCertificates[i]

		if first == true {
			fmt.Printf("\n++++ Certificate Chain\n")
			first = false
		} else {
			fmt.Printf("\n++++ Next Certificate\n")
		}
		if cert.BasicConstraintsValid == true && cert.IsCA == true {
			fmt.Printf("RootCA Serial Number: %v\n", cert.SerialNumber)
		} else {
			fmt.Printf("Serial Number: %v\n", cert.SerialNumber)
		}

		fmt.Printf("Subject Common Name: %s\n", cert.Subject.CommonName)

		if len(cert.DNSNames) > 0 {
			fmt.Printf("DNSNames: ")
			for _, dnsname := range cert.DNSNames {
				fmt.Printf("%s, ", dnsname)
			}
			fmt.Printf("\n")
		}

		if config.verbose == true {
			fmt.Printf("Not Before:\t%s\nNot After:\t%s\n", cert.NotBefore.String(), cert.NotAfter.String())
		}
	}

	tlscert.Close()

	os.Exit(0)
}

/*

 */
