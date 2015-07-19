package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// getSSLVersion will return the string name for a tls constant version number
func getSSLVersion(v uint16) string {

	switch v {
	case tls.VersionSSL30:
		return "SSLv3.0"
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	default:
	}
	return "Unknown Protocol"
}

// getCipher will return the string name for a tls constanct cipher numner
func getCipher(c uint16) string {

	switch c {
	case tls.TLS_RSA_WITH_RC4_128_SHA:
		return "TLS_RSA_WITH_RC4_128_SHA"
	case tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
		return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
		return "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
	case tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_FALLBACK_SCSV:
		return "TLS_FALLBACK_SCSV"

	default:
	}

	return "Unknown Cipher"
}

// protocolScan creates a go routine to test a connection for a particular protocol
// It also creates a channel to return the results to func main
func protocolScan(p uint16, host string) <-chan string {
	c := make(chan string)

	//
	go func(p uint16, host string) {

		var rs string

		//
		dialConfig := &net.Dialer{
			DualStack: true,
			Timeout:   (time.Second * 10),
		}

		tlsConfig := &tls.Config{
			InsecureSkipVerify:       true,
			PreferServerCipherSuites: true,
			MinVersion:               p,
			MaxVersion:               p,
		}

		tlsconn, err := tls.DialWithDialer(dialConfig, "tcp", host, tlsConfig)

		if err != nil {
			rs = fmt.Sprintf("Failed - Protocol %s: Error: %s", getSSLVersion(p), err.Error())
		} else {

			cs := tlsconn.ConnectionState()

			if cs.HandshakeComplete == true {
				rs = fmt.Sprintf("Connected - Protocol: %s\tCipher: %s", getSSLVersion(cs.Version), getCipher(cs.CipherSuite))
			} else {
				rs = fmt.Sprintf("Error - TLS Handshake not completed. Unable to get connection details")
			}
			tlsconn.Close()
		}

		// goroutine has done its work so return the result
		c <- rs

	}(p, host)

	return c

}

/*

 */
