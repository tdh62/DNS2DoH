package main

import (
	"encoding/base64"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

const (
	listenAddress = "" // listen address
	listenPort    = 53 // port
	protrol       = "udp4"
	DoHAddress    = "https://223.5.5.5"
	DoHPath       = "/dns-query"
)

var DoHEndPoints string

func main() {
	// Read param from command line
	a := os.Args[1:]
	if len(a) >= 1 {
		DoHEndPoints = os.Args[1]
	} else {
		DoHEndPoints = ""
	}

	// Build UDP listener
	conn, err := net.ListenUDP(protrol, &net.UDPAddr{IP: net.ParseIP(listenAddress).To4(), Port: listenPort})
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// handle Connect
	handleConn(conn)
}

// handleConn Handle UDP DNS request
func handleConn(con *net.UDPConn) {
	for {
		// Receive data and base64 URL encoding
		buf := make([]byte, 2048)
		ri, rmt, err := con.ReadFromUDP(buf)
		if err != nil {
			log.Println(err)
			continue
		}
		b64req := base64.URLEncoding.EncodeToString(buf[:ri])

		// Forward response from DoH to UDP
		_, err = con.WriteToUDP(doDoHRequest(b64req), rmt)
		if err != nil {
			log.Println(err)
		}
	}
}

// doDoHRequest Do DoH request and return response data as []byte
func doDoHRequest(b64req string) []byte {
	// remove "=" from base64 data
	b64req = strings.Replace(b64req, "=", "", -1)

	// build HTTP GET request
	c := http.Client{}
	var url string
	if DoHEndPoints == "" {
		url = DoHAddress + DoHPath + "?dns=" + b64req
	} else {
		url = DoHAddress + DoHPath + "?dns=" + b64req
	}
	r, err := http.NewRequest(http.MethodGet, url, nil)
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
	_, err = resp.Body.Read(sbuf)
	if err != nil {
		log.Println(err)
	}
	return sbuf
}
