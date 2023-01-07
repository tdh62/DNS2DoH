package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	Version = "v1.2"
	License = "MIT License"
	TimeOut = time.Second * 30
)

type Config struct {
	ListenAddress string //  "" // listen address
	ListenTCP     bool   // true
	TCPPort       int    //  53 // port
	ListenUDP     bool   // true
	UDPPort       int    //  53 // port
	ForwardTo     string // "DoH"
	EndPoint      string // "dns.pub"
	ServerName    string // "dns.pub"
	ParseRequest  bool
}

var config = Config{
	ListenAddress: "",
	ListenTCP:     true,
	TCPPort:       53,
	ListenUDP:     true,
	UDPPort:       53,
	ForwardTo:     "DoH",
	EndPoint:      "dns.pub",
	ServerName:    "dns.pub",
	ParseRequest:  true,
}

// loadConfig load the config from command line or config.json file
func loadConfig() {
	flag.StringVar(&config.ListenAddress, "ip", "127.0.0.1", "Define the listen address")
	notcp := flag.Bool("notcp", false, "Disable listen on TCP")
	noudp := flag.Bool("noudp", false, "Disable listen on UDP")
	flag.IntVar(&config.TCPPort, "port", 53, "Set listen port on TCP.")
	flag.IntVar(&config.UDPPort, "udpport", 53, "Set listen port on UDP.")
	flag.StringVar(&config.ForwardTo, "to", "DoH", "Only 'DoH' or 'DoT' can be use to define wherever "+
		"the data froward to.")
	flag.StringVar(&config.EndPoint, "e", "https://1.12.12.12/dns-query", "Set Target of DoH or DoT "+
		"server, if use DoH, Please input the FULL address, including 'https://' and path such as '/dns-query'.")
	flag.StringVar(&config.ServerName, "sni", "", "For TLS handshake, If empty the vitrify of TLS will"+
		" be disabled.")
	//flag.BoolVar(&config.ParseRequest, "parse", false, "Parse the request and response."+
	//	"It's useless now because not cache or setter live.")
	flag.Parse()
	if *notcp {
		config.ListenTCP = false
	}
	if *noudp {
		config.ListenUDP = false
	}
	if config.ForwardTo == "DoH" {
		parse, err := url.Parse(config.EndPoint)
		if err != nil {
			log.Fatal(err)
		}
		config.EndPoint = parse.String()
	}
	if config.ForwardTo == "DoT" {
		if strings.Index(config.EndPoint, ":") < 0 {
			config.EndPoint += ":853"
		}
	}
}

func main() {
	log.Println("DNS2DoH version", Version, ",Following", License)
	loadConfig()

	// start listener
	udpChan := make(chan struct{})
	tcpChan := make(chan struct{})
	var listener int
	if config.ListenUDP {
		log.Println("Starting UDP Listener")
		listener++
		go UDPListener(udpChan)
	}

	if config.ListenTCP {
		log.Println("Starting TCP Listener")
		listener++
		go TCPListener(tcpChan)
	}

	// wait listener down
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
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(config.ListenAddress).To4(), Port: config.UDPPort})
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
	conn, err := net.Listen("tcp", config.ListenAddress+":"+strconv.Itoa(config.TCPPort))
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

// setConnTimeout to set the deadline of connection
func setConnTimeout(con net.Conn, timeout time.Duration) {
	_ = net.Conn.SetDeadline(con, time.Now().Add(timeout))
}

func handleTCPConn(con net.Conn) {
	for {
		// Set/Update timeout
		setConnTimeout(con, TimeOut)

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

		switch config.ForwardTo {
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

		if config.ParseRequest {
			d, _ := parseDomain(buf[12:ri])
			t := binary.BigEndian.Uint16(buf[ri-4 : ri-2])
			var tp string
			switch t {
			case 0x01:
				tp = "IPv4(A)"
			case 0x1c:
				tp = "IPv6(AAAA)"
			default:
				tp = "other"
			}
			log.Printf("Forwarding request %s %s address.", d, tp)
		}
		// Forward response
		go forwardToUDP(con, buf[:ri], rmt)

	}
}

func forwardToUDP(con *net.UDPConn, buf []byte, rmt *net.UDPAddr) {
	var err error
	switch config.ForwardTo {
	case "DoH":
		_, err = con.WriteToUDP(doDoHRequest(buf), rmt)
	case "DoT":
		_, err = con.WriteToUDP(doDoTRequest(buf), rmt)
	default:
		panic("Error forward target.")
	}
	if err != nil {
		log.Println(err)
	}
}

// doDoHRequest Do DoH request and return response data as []byte
func doDoHRequest(buf []byte) []byte {
	b64req := base64.URLEncoding.EncodeToString(buf)

	// remove "=" from base64 data
	b64req = strings.Replace(b64req, "=", "", -1)

	// build HTTP GET request
	c := http.Client{}
	r, err := http.NewRequest(http.MethodGet, config.EndPoint+"?dns="+b64req, nil)
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
	n, err := net.Dial("tcp", config.EndPoint)
	if err != nil {
		log.Println(err)
		return nil
	}
	defer func(n net.Conn) {
		_ = n.Close()
	}(n)
	tn := parseTLS(n, config.ServerName == "", config.ServerName)

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
	setConnTimeout(tn, TimeOut)
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

func parseDomain(rbuf []byte) (string, int) {
	domain := ""
	offset := 0

	for {
		if rbuf[offset] == 0 {
			offset += 1
			return domain[:len(domain)-1], offset
		} else if rbuf[offset]&0xc0 == 0xc0 {
			// Pointer
			p := binary.BigEndian.Uint16(rbuf[offset:offset+2]) & 0x3fff
			d, _ := parseDomain(rbuf[p:])
			domain += d
			offset += 2
			return domain[:len(domain)-1], offset
		} else {
			// domain
			l := int(rbuf[offset])
			domain += string(rbuf[offset+1:offset+1+l]) + "."
			offset += l + 1
		}
	}
}
