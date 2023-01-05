package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	listenAddress = "" // listen address
	listenPort    = 53 // port
	listenUDP     = true
	listenTCP     = true
	forwardTo     = "DoH" // DoH or DoT can be used
	DoTEndPoint   = "dns.pub"
	ServerName    = "dns.pub"
)

var DoHEndPoint = "https://1.12.12.12/dns-query"

func main() {
	// Read param from command line
	a := os.Args[1:]
	if len(a) >= 1 {
		DoHEndPoint = os.Args[1]
	}
	udpChan := make(chan struct{})
	tcpChan := make(chan struct{})
	var listener int
	if listenUDP {
		listener++
		go UDPListener(udpChan)
	}
	if listenTCP {
		listener++
		go TCPListener(tcpChan)
	}
	for listener > 0 {
		select {
		case <-udpChan:
			log.Println("UDP Listener is down.")
			listener--
		case <-tcpChan:
			log.Println("TCP Listener is down.")
			listener--
		}
	}
	log.Println("All listener is down, exit.")
}

// UDPListener Build UDP listener
func UDPListener(down chan struct{}) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(listenAddress).To4(), Port: listenPort})
	if err != nil {
		log.Println(err)
		down <- struct{}{}
		return
	}
	defer func(conn *net.UDPConn) {
		_ = conn.Close()
	}(conn)

	// handle Connect
	handleUDPConn(conn)
	down <- struct{}{}
}

func TCPListener(down chan struct{}) {
	conn, err := net.Listen("tcp", listenAddress+":"+strconv.Itoa(listenPort))
	if err != nil {
		log.Println(err)
		down <- struct{}{}
		return
	}
	defer func(conn net.Listener) {
		_ = conn.Close()
	}(conn)
	for {
		cn, err := conn.Accept()
		if err != nil {
			log.Println(err)
			break
		}
		handleTCPConn(cn)
		_ = cn.Close()
	}
	down <- struct{}{}
}

func handleTCPConn(con net.Conn) {
	for {
		// Set/Update timeout
		_ = net.Conn.SetDeadline(con, time.Now().Add(time.Second*30))
		buf := make([]byte, 2048)
		ri, err := con.Read(buf)
		if err != nil {
			return
		}
		var x int16
		bytesBuffer := bytes.NewBuffer(buf)
		err = binary.Read(bytesBuffer, binary.BigEndian, &x)
		if err != nil {
			return
		}

		// if data transform not complete, wait it before finish
		for ri < int(x)+2 {
			tbuf := make([]byte, 2048)
			tri, err := con.Read(tbuf)
			if err != nil {
				return
			}
			buf = append(buf[:ri], tbuf[:tri]...)
			ri += tri
		}
		if int(x)+2 < ri {
			log.Println("Error request message len.")
			return
		}

		switch forwardTo {
		case "DoH":
			_, err = con.Write(addLen(doDoHRequest(buf[2:ri])))
		case "DoT":
			_, err = con.Write(addLen(doDoTRequest(buf[2:ri])))
		default:
			panic("Error forward target.")
		}
	}

}

func addLen(buf []byte) []byte {
	l := int16(len(buf))
	lbuf := bytes.NewBuffer([]byte{})
	_ = binary.Write(lbuf, binary.BigEndian, l)
	nbuf := lbuf.Bytes()
	nbuf = append(nbuf, buf...)
	return nbuf
}

// handleUDPConn Handle UDP DNS request
func handleUDPConn(con *net.UDPConn) {
	for {
		// Receive data and base64 URL encoding
		buf := make([]byte, 2048)
		ri, rmt, err := con.ReadFromUDP(buf)
		if err != nil {
			log.Println(err)
			continue
		}

		// Forward response
		switch forwardTo {
		case "DoH":
			_, err = con.WriteToUDP(doDoHRequest(buf[:ri]), rmt)
		case "DoT":
			_, err = con.WriteToUDP(doDoTRequest(buf[:ri]), rmt)
		default:
			panic("Error forward target.")
		}

		if err != nil {
			log.Println(err)
		}
	}
}

// doDoHRequest Do DoH request and return response data as []byte
func doDoHRequest(buf []byte) []byte {
	b64req := base64.URLEncoding.EncodeToString(buf)

	// remove "=" from base64 data
	b64req = strings.Replace(b64req, "=", "", -1)

	// build HTTP GET request
	c := http.Client{}
	r, err := http.NewRequest(http.MethodGet, DoHEndPoint+"?dns="+b64req, nil)
	if err != nil {
		log.Println(err)
		return nil
	}
	r.Header.Set("Content-Type", "application/dns-message")
	resp, err := c.Do(r)
	if err != nil {
		log.Println(err)
		return nil
	}
	// Do GET request and read response
	sbuf := make([]byte, resp.ContentLength)
	if resp.StatusCode != 200 {
		log.Println(resp.Body)
	}
	ri, err := resp.Body.Read(sbuf)
	if err != nil {
		log.Println(err)
	}
	return sbuf[:ri]
}

// parseTLS build TLS link on an opening net.Conn connect
func parseTLS(n net.Conn, skipVerify bool, sniName string) *tls.Conn {
	tlsconfig := &tls.Config{
		InsecureSkipVerify: skipVerify, // true if skip verify certificate
		ServerName:         sniName,    // ServerName if endpoints is IP address and InsecureSkipVerify is false
	}
	tn := tls.Client(n, tlsconfig)
	err := tn.Handshake()
	if err != nil {
		log.Println(err)
		return nil
	}
	return tn
}

func doDoTRequest(buf []byte) []byte {
	// counting the message len
	nbuf := addLen(buf)

	// dial DoT server
	t := DoTEndPoint
	if strings.Index(DoTEndPoint, ":") < 0 {
		t += ":853"
	}
	n, err := net.Dial("tcp", t)
	if err != nil {
		log.Println(err)
		return nil
	}
	defer func(n net.Conn) {
		_ = n.Close()
	}(n)
	tn := parseTLS(n, ServerName == "", ServerName)

	// Send Request and receive response
	_, err = tn.Write(nbuf)
	if err != nil {
		log.Println(err)
		return nil
	}
	rbuf := make([]byte, 4096)
	ri, err := tn.Read(rbuf)
	if err != nil {
		return nil
	}
	_ = net.Conn.SetDeadline(tn, time.Now().Add(time.Second*20))
	bytesBuffer := bytes.NewBuffer(rbuf)
	var x int16
	err = binary.Read(bytesBuffer, binary.BigEndian, &x)
	if err != nil {
		return nil
	}
	for ri < int(x)+2 {
		tbuf := make([]byte, 2048)
		tri, err := tn.Read(tbuf)
		if err != nil {
			return nil
		}
		rbuf = append(rbuf[:ri], tbuf[:tri]...)
		ri += tri
	}
	if int(x)+2 < ri {
		log.Println("Error response message len.")
		return nil
	}

	return rbuf[2:ri]
}
