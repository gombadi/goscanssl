/*
Package main provides a small cli application to display information about SSL connections and certificates.

Usage of goscanssl:
  -a    Display all info
  -cert
        Display Certificate info
  -conn
        Display Connection info
  -e    Display Certificate expire info in CSV format
  -h string
        Remote host to test
  -p string
        Remote port to connect to. (default "443")
  -v    Display verbose output

*/
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"time"
)

// goscanssl contains all the application config data
type goscanssl struct {
	host    string
	port    string
	cert    bool
	conn    bool
	expire  bool
	all     bool
	verbose bool
}

// showExpire will display one csv line showing the certificate expire date and any
// DNS Names associated with the certificate
func showExpire(config *goscanssl) {

	tlscert, err := tls.Dial("tcp", config.host+":"+config.port, &tls.Config{InsecureSkipVerify: true})

	if err != nil {
		fmt.Printf("Unable to get Certificate details: %s\n", err.Error())
		return
	}

	if cert := tlscert.ConnectionState().PeerCertificates[0]; cert != nil {

		fmt.Printf("%s,%dhrs,", cert.NotAfter.String(), int(cert.NotAfter.Sub(time.Now()).Hours()))

		if len(cert.DNSNames) > 0 {
			for _, dnsname := range cert.DNSNames {
				fmt.Printf("%s,", dnsname)
			}
		}
		fmt.Printf("\n")
	}
	tlscert.Close()
}

// scanCert will display information about the SSL certificate presented by the remote host
func scanCert(config *goscanssl) {

	tlscert, err := tls.Dial("tcp", config.host+":"+config.port, &tls.Config{InsecureSkipVerify: true})

	if err != nil {
		fmt.Printf("Unable to get Certificate details: %s\n", err.Error())
		return
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
}

// scanProtocol will test SSL connections to remote host with each SSL/TLS protocol available
// and display the results
func scanProtocol(host string) {

	// start goroutines for each protocol and get a chan to receive the results
	ssl30 := protocolScan(tls.VersionSSL30, host)
	tls10 := protocolScan(tls.VersionTLS10, host)
	tls11 := protocolScan(tls.VersionTLS11, host)
	tls12 := protocolScan(tls.VersionTLS12, host)

	// wait for and then print the results from each goroutine in the order we want
	fmt.Println(<-ssl30)
	fmt.Println(<-tls10)
	fmt.Println(<-tls11)
	fmt.Println(<-tls12)

}

// main is the application start point
func main() {

	var config goscanssl

	flag.BoolVar(&config.conn, "conn", false, "Display Connection info")
	flag.BoolVar(&config.cert, "cert", false, "Display Certificate info")
	flag.BoolVar(&config.all, "a", false, "Display all info")
	flag.BoolVar(&config.expire, "e", false, "Display Certificate expire info in CSV format")
	flag.StringVar(&config.host, "h", "", "Remote host to test")
	flag.StringVar(&config.port, "p", "443", "Remote port to connect to.")
	flag.BoolVar(&config.verbose, "v", false, "Display verbose output")
	flag.Parse()

	if config.host == "" {
		fmt.Printf("Error: No host provided\n")
		os.Exit(1)
	}

	if config.expire == true {
		showExpire(&config)
		os.Exit(0)
	}

	if config.conn == false && config.cert == false {
		config.all = true
	}

	if config.conn == true || config.all == true {
		scanProtocol(config.host + ":" + config.port)
	}

	if config.cert == true || config.all == true {
		scanCert(&config)
	}
	os.Exit(0)
}

/*

 */
