package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	tls "github.com/refraction-networking/utls"
)

type ClientSessionCache struct {
	sessionKeyMap map[string]*tls.ClientSessionState
}

func NewClientSessionCache() tls.ClientSessionCache {
	return &ClientSessionCache{
		sessionKeyMap: make(map[string]*tls.ClientSessionState),
	}
}

func (csc *ClientSessionCache) Get(sessionKey string) (session *tls.ClientSessionState, ok bool) {
	if session, ok = csc.sessionKeyMap[sessionKey]; ok {
		fmt.Printf("Getting session for %s\n", sessionKey)
		return session, true
	}
	fmt.Printf("Missing session for %s\n", sessionKey)
	return nil, false
}

func (csc *ClientSessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {
	if cs == nil {
		fmt.Printf("Deleting session for %s\n", sessionKey)
		delete(csc.sessionKeyMap, sessionKey)
	} else {
		fmt.Printf("Putting session for %s\n", sessionKey)
		csc.sessionKeyMap[sessionKey] = cs
	}
}

type ResumptionType int

const (
	noResumption     ResumptionType = 0
	pskResumption    ResumptionType = 1
	ticketResumption ResumptionType = 2
)

func runResumptionCheck(helloID tls.ClientHelloID, getCustomSpec func() *tls.ClientHelloSpec, expectResumption ResumptionType, serverAddr string, retry int, verbose bool) {
	fmt.Printf("checking: hello [%s], expectResumption [%v], serverAddr [%s]\n", helloID.Client, expectResumption, serverAddr)
	csc := NewClientSessionCache()
	tcpConn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		panic(err)
	}

	// Everything below this line is brought to you by uTLS API, enjoy!

	// use chs
	tlsConn := tls.UClient(tcpConn, &tls.Config{
		ServerName: strings.Split(serverAddr, ":")[0],
		// NextProtos:         []string{"h2", "http/1.1"},
		ClientSessionCache: csc, // set this so session tickets will be saved
		OmitEmptyPsk:       true,
	}, helloID)

	if getCustomSpec != nil {
		tlsConn.ApplyPreset(getCustomSpec())
	}

	// HS
	err = tlsConn.Handshake()
	if err != nil {
		panic(err)
	}

	var tlsVer uint16

	if tlsConn.ConnectionState().HandshakeComplete {
		tlsVer = tlsConn.ConnectionState().Version
		if verbose {
			fmt.Println("Handshake complete")
			fmt.Printf("TLS Version: %04x\n", tlsVer)
		}
		if tlsVer == tls.VersionTLS13 {
			if verbose {
				fmt.Printf("Expecting PSK resumption\n")
			}
		} else if tlsVer == tls.VersionTLS12 {
			if verbose {
				fmt.Printf("Expecting session ticket resumption\n")
			}
		} else {
			panic("Don't try resumption on old TLS versions")
		}

		if tlsConn.HandshakeState.State13.UsingPSK {
			panic("unintended using of PSK happened...")
		} else if tlsConn.DidTls12Resume() {
			panic("unintended using of session ticket happened...")
		} else {
			if verbose {
				fmt.Println("First connection, no PSK/session ticket to use.")
			}
		}

		tlsConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		tlsConn.Read(make([]byte, 1024)) // trigger a read so NewSessionTicket gets handled
	}
	tlsConn.Close()

	resumption := noResumption
	for i := 0; i < retry; i++ {
		tcpConnPSK, err := net.Dial("tcp", serverAddr)
		if err != nil {
			panic(err)
		}

		tlsConnPSK := tls.UClient(tcpConnPSK, &tls.Config{
			ServerName:         strings.Split(serverAddr, ":")[0],
			ClientSessionCache: csc,
			OmitEmptyPsk:       true,
		}, helloID)

		if getCustomSpec != nil {
			tlsConnPSK.ApplyPreset(getCustomSpec())
		}

		// HS
		err = tlsConnPSK.Handshake()
		if verbose {
			fmt.Printf("tlsConnPSK.HandshakeState.Hello.Raw %v\n", tlsConnPSK.HandshakeState.Hello.Raw)
			fmt.Printf("tlsConnPSK.HandshakeState.Hello.PskIdentities: %v\n", tlsConnPSK.HandshakeState.Hello.PskIdentities)
		}

		if err != nil {
			panic(err)
		}

		if tlsConnPSK.ConnectionState().HandshakeComplete {
			if verbose {
				fmt.Println("Handshake complete")
			}
			newVer := tlsConnPSK.ConnectionState().Version
			if verbose {
				fmt.Printf("TLS Version: %04x\n", newVer)
			}
			if newVer != tlsVer {
				panic("Tls version changed unexpectedly on the second connection")
			}

			if tlsVer == tls.VersionTLS13 && tlsConnPSK.HandshakeState.State13.UsingPSK {
				fmt.Println("[PSK used]")
				resumption = pskResumption
				break
			} else if tlsVer == tls.VersionTLS12 && tlsConnPSK.DidTls12Resume() {
				fmt.Println("[session ticket used]")
				resumption = ticketResumption
				break
			}
		}
		time.Sleep(700 * time.Millisecond)
	}

	if resumption != expectResumption {
		panic(fmt.Sprintf("Expecting resumption type: %v, actual %v; session, server %s, helloID: %s", expectResumption, resumption, serverAddr, helloID.Client))
	} else {
		fmt.Println("[expected]")
	}
}

func main() {
	tls13Url := "www.microsoft.com:443"
	tls13HRRUrl := "marketplace.visualstudio.com:443" // will send HRR for P384/P521
	tls12Url := "tls-v1-2.badssl.com:1012"
	runResumptionCheck(tls.HelloChrome_100, nil, noResumption, tls13Url, 3, false) // no-resumption + utls
	func() {
		defer func() {
			if err := recover(); err == nil {
				panic("must throw")
			}
		}()

		runResumptionCheck(tls.HelloCustom, func() *tls.ClientHelloSpec {
			spec, _ := tls.UTLSIdToSpec(tls.HelloChrome_100)
			return &spec
		}, noResumption, tls13Url, 3, false) // no-resumption + utls custom + no psk extension
	}()
	runResumptionCheck(tls.HelloChrome_100_PSK, nil, pskResumption, tls13Url, 1, false) // psk + utls
	runResumptionCheck(tls.HelloGolang, nil, pskResumption, tls13Url, 1, false)         // psk + crypto/tls

	runResumptionCheck(tls.HelloChrome_100_PSK, nil, pskResumption, tls13HRRUrl, 20, false) // psk (HRR) + utls
	runResumptionCheck(tls.HelloGolang, nil, pskResumption, tls13HRRUrl, 20, false)         // psk (HRR) + crypto/tls

	runResumptionCheck(tls.HelloChrome_100_PSK, nil, ticketResumption, tls12Url, 10, false) // session ticket + utls
	runResumptionCheck(tls.HelloGolang, nil, ticketResumption, tls12Url, 10, false)         // session ticket + crypto/tls
}
