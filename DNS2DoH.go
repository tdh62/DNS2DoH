package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	Version = "v1.3"
	License = "MIT License"
	TimeOut = time.Second * 30
)

type DNSHeader struct {
	ID      uint16 // Request ID
	FLAGS   uint16 // Flags
	QDCOUNT uint16 // Question
	ANCOUNT uint16 // Answer
	NSCOUNT uint16 // NS response will drop when build a response
	ARCOUNT uint16 // AR request will be ignored when parser
}

type DNSRequest struct {
	HD     DNSHeader // Headers
	Domain string
	QType  uint16
	QClass uint16 // Only IN support
}

type Trie struct {
	Child map[rune]*Trie
	IsEnd bool
}

// reverseString use to reverse a string input
func reverseString(s string) string {
	var result []rune
	for _, v := range s {
		result = append(result, v)
	}

	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return string(result)
}

// Insert used to insert string to Trie tree
func (t *Trie) Insert(s string) {
	s = reverseString(s)
	var p *Trie
	p = t
	for _, r := range s {
		if _, ok := p.Child[r]; !ok {
			p.Child[r] = NewTrie()
		}
		p = p.Child[r]
	}
	p.IsEnd = true
}

func (t *Trie) hasSuffix(s string) bool {
	s = reverseString(s)
	p := t
	for _, r := range s {
		if _, ok := p.Child[r]; ok == false {
			return p.IsEnd
		}
		p = p.Child[r]
		if p.IsEnd == true {
			return true
		}
	}
	return p.IsEnd
}

func NewTrie() *Trie {
	return &Trie{Child: map[rune]*Trie{}, IsEnd: false}
}

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
	BanList       Trie
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
	BanList:       *NewTrie(),
}

func main() {
	log.Println("DNS2DoH version", Version, ",Following", License)
	loadConfig()
	loadBanList()

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

// loadConfig load the config from command line or config.json file
func loadConfig() {
	flag.StringVar(&config.ListenAddress, "ip", "127.0.0.1", "Define the listen address")
	notcp := flag.Bool("notcp", false, "Disable listen on TCP")
	noudp := flag.Bool("noudp", false, "Disable listen on UDP")
	flag.IntVar(&config.TCPPort, "port", 53, "Set listen port on TCP.")
	flag.IntVar(&config.UDPPort, "udpport", 53, "Set listen port on UDP.")
	flag.StringVar(&config.ForwardTo, "to", "DoH", "Only 'DoH' or 'DoT' can be use to define wherever "+
		"the data froward to.")
	flag.StringVar(&config.EndPoint, "e", "https://doh.pub/dns-query", "Set Target of DoH or DoT "+
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

func loadBanList() {
	_, err := os.Stat("ban.txt")
	if os.IsNotExist(err) {
		return
	}
	fi, err := os.Open("ban.txt")
	if err != nil {
		log.Println(err)
		return
	}
	rd := bufio.NewReader(fi)

	for {
		ln, err := rd.ReadString('\n')
		if err != nil && err != io.EOF {
			log.Println(err)
			return
		}
		for {
			if ln[len(ln)-1] == 10 {
				ln = ln[:len(ln)-1]
			} else if ln[len(ln)-1] == 13 {
				ln = ln[:len(ln)-1]
			} else {
				break
			}
		}
		ln = strings.Trim(ln, "\n")
		config.BanList.Insert(ln)
		if err == io.EOF {
			return
		}
	}

}

// setConnTimeout to set the deadline of connection
func setConnTimeout(con net.Conn, timeout time.Duration) {
	_ = net.Conn.SetDeadline(con, time.Now().Add(timeout))
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
			parseRequest(buf[:ri])
			d, _ := parseDomain(buf[12:ri])
			//t := binary.BigEndian.Uint16(buf[ri-4 : ri-2])
			d = reverseString(d)
			baned := banCheck(d)
			if baned {
				// set QR as response and return
				buf[2] = buf[2] | 0x80 // 1000 0000 just set QR to 1 (response)
				go func() {
					_, _ = con.WriteToUDP(buf[:ri], rmt)
				}()
				continue
			}

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

func banCheck(revd_d string) bool {
	revd_d = reverseString(revd_d)
	if config.BanList.hasSuffix(revd_d) {
		return true
	} else {
		return false
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

func parseHeader(rbuf []byte, HD *DNSHeader) {
	HD.ID = binary.BigEndian.Uint16(rbuf[0:2])
	HD.FLAGS = binary.BigEndian.Uint16(rbuf[2:4])
	HD.QDCOUNT = binary.BigEndian.Uint16(rbuf[4:6])
	HD.ANCOUNT = binary.BigEndian.Uint16(rbuf[6:8])
	HD.NSCOUNT = binary.BigEndian.Uint16(rbuf[8:10])
	HD.ARCOUNT = binary.BigEndian.Uint16(rbuf[10:12])
}

func parseRequest(rbuf []byte) {
	var req DNSRequest
	parseHeader(rbuf, &req.HD)
	var o int
	req.Domain, o = parseDomain(rbuf[12:])
	req.QType = binary.BigEndian.Uint16(rbuf[12+o : 12+o+2])
	req.QClass = binary.BigEndian.Uint16(rbuf[12+o+2 : 12+o+4])
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

//func parseAnswer(fullbuf []byte, offset int, ANCOUNT int) {
//	for i := 0; i < int(ANCOUNT); i++ {
//		domain, offset := parseDomain(fullbuf[offset:])                    // 解析域名
//		qType := binary.BigEndian.Uint16(fullbuf[offset : offset+2])       // 请求类型
//		qClass := binary.BigEndian.Uint16(fullbuf[offset+2 : offset+4])    // 请求类
//		ttl := binary.BigEndian.Uint32(fullbuf[offset+4 : offset+8])       // TTL
//		rdLength := binary.BigEndian.Uint16(fullbuf[offset+8 : offset+10]) // 资源记录数据长度
//		rData := fullbuf[offset+10 : offset+10+int(rdLength)]              // 资源记录数据
//		offset += int(rdLength)
//	}
//}
