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
	"sync"
	"time"
)

const (
	Version = "v1.3"
	License = "MIT License"
	TimeOut = time.Second * 30
)

type Cache struct {
	c   sync.Map
	cnt int
}

type DNSCacheKey struct {
	domain string
	v6     bool // true for IPv6, false for IPv4
}

// DNSCache cache
type DNSCache struct {
	AList  [][]byte
	Expiry int64
}

func (c *Cache) clean() {
	c.c.Range(func(key, value interface{}) bool {
		if c.cnt > config.MaxCache {
			c.c.Delete(key)
			c.cnt--
		}
		return true
	})
}

func (c *Cache) Set(key DNSCacheKey, value [][]byte, duration int) {
	exp := time.Now().Add(time.Second * time.Duration(duration)).Unix()
	c.c.Store(key, DNSCache{AList: value, Expiry: exp})
	c.cnt++
	if config.MaxCache > 0 {
		if c.cnt > config.MaxCache {
			c.clean()
		}
	}
}

func (c *Cache) Get(key DNSCacheKey) ([][]byte, bool) {
	var empty interface{}
	empty = key
	entry, ok := c.c.Load(empty)
	if !ok {
		return nil, false
	}
	e, ok := entry.(DNSCache)
	if !ok {
		return nil, false
	}
	if e.Expiry < time.Now().Unix() {
		c.c.Delete(key)
		c.cnt--
		return nil, false
	}
	return e.AList, true
}

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
			return false
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
	MaxCache      int
	CacheExpiry   int // cache time (s)
}

var config = Config{
	ListenAddress: "",
	ListenTCP:     true,
	TCPPort:       53,
	ListenUDP:     true,
	UDPPort:       53,
	ForwardTo:     "DoH",
	EndPoint:      "https://1.12.12.12/dns-query",
	ServerName:    "dns.pub",
	ParseRequest:  true,
	BanList:       *NewTrie(),
	MaxCache:      1000 * 8,
	CacheExpiry:   600,
}

var cache = Cache{cnt: 0}

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
	flag.StringVar(&config.EndPoint, "e", "https://1.12.12.12/dns-query", "Set Target of DoH or DoT "+
		"server, if use DoH, Please input the FULL address, including 'https://' and path such as '/dns-query'.")
	flag.StringVar(&config.ServerName, "sni", "", "For TLS handshake, If empty the vitrify of TLS will"+
		" be disabled.")
	//flag.BoolVar(&config.ParseRequest, "parse", false, "Parse the request and response."+
	//	"It's useless now because not cache or setter live.")
	flag.IntVar(&config.MaxCache, "maxcache", 4*1000, "The max value of cache.")
	flag.IntVar(&config.CacheExpiry, "cachetime", 3600, "The max value of cache(s).")
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
	defer func(fi *os.File) {
		_ = fi.Close()
	}(fi)
	rd := bufio.NewReader(fi)

	for {
		ln, err := rd.ReadString('\n')
		if err != nil && err != io.EOF {
			log.Println(err)
			return
		}

		for {
			if len(ln) == 0 {
				break
			}
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

func BanOrCache(rbuf []byte) ([]byte, bool) {
	if config.ParseRequest {
		parseRequest(rbuf[:])
		d, dlen := parseDomain(rbuf, 12)
		ri := len(rbuf)
		baned := banCheck(d)
		if baned {
			// set QR as response and return
			rbuf[2] = rbuf[2] | 0x80 // 1000 0000 just set QR to 1 (response)
			return rbuf, true
		}

		// search cache
		t := binary.BigEndian.Uint16(rbuf[ri-4 : ri-2])
		var k DNSCacheKey
		if t == 0x1c {
			// AAAA request
			k = DNSCacheKey{
				domain: d,
				v6:     true,
			}
		} else if t == 0x01 {
			// A request
			k = DNSCacheKey{
				domain: d,
				v6:     false,
			}
		} else {
			// just A or AAAA can be cached
			return nil, false
		}
		cacheData, ok := cache.Get(k)
		if ok == false {
			return nil, false
		}
		al := uint16(len(cacheData))
		// build DNS response
		bb := bytes.NewBuffer([]byte{})

		// DNSHeader
		rl := 0
		rbuf[2] = rbuf[2] | 0x80
		bb.Write(rbuf[0:4])                        // DNSHeader
		bb.Write([]byte{0, 1})                     // QDCount
		_ = binary.Write(bb, binary.BigEndian, al) // QDCount
		bb.Write([]byte{0, 0})                     // NSCount
		bb.Write([]byte{0, 0})                     // ARCount
		bb.Write(rbuf[12 : 12+dlen+4])             //Question
		rl += 12 + dlen + 4
		for _, al := range cacheData {
			bb.Write(al)
			rl += len(al)
		}
		return bb.Bytes(), true
	}
	return nil, false
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
		hit, ok := BanOrCache(buf[:ri])
		if ok {
			go func() {
				_, _ = con.WriteToUDP(hit, rmt)
			}()
			continue
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
		hit, ok := BanOrCache(buf[:ri])
		if ok {
			go func() {
				_, _ = con.Write(addLen(hit))
			}()
			continue
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

func banCheck(d string) bool {
	if config.BanList.hasSuffix(d) {
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
		if resp.StatusCode == 502 {
			d, _ := parseDomain(buf, 12)
			if d != "" {
				config.BanList.Insert(d)
				_ = appendToFile("ban.txt", d+"\n")
			}
		}
		log.Println(resp.Body)
		return nil
	}
	ri, err := resp.Body.Read(sbuf)
	if err != nil {
		log.Println(err)
	}
	saveToCahce(sbuf[:ri])
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
	req.Domain, o = parseDomain(rbuf, 12)
	req.QType = binary.BigEndian.Uint16(rbuf[12+o : 12+o+2])
	req.QClass = binary.BigEndian.Uint16(rbuf[12+o+2 : 12+o+4])
}

func parseDomain(rbuf []byte, offset int) (string, int) {
	rof := offset
	domain := ""
	defer func() {
		if e := recover(); e != nil {
			log.Println(e)
			log.Println("Unable to parse domain", domain)
		}
	}()
	for {
		if rbuf[offset] == 0 {
			offset += 1
			if domain[len(domain)-1] == '.' {
				domain = domain[:len(domain)-1]
			}
			return domain, offset - rof
		} else if rbuf[offset]&0xc0 == 0xc0 {
			// Pointer
			p := binary.BigEndian.Uint16(rbuf[offset:offset+2]) & 0x3fff
			d, _ := parseDomain(rbuf, int(p))
			domain += d
			offset += 2
			return domain, offset - rof
		} else {
			// domain
			l := int(rbuf[offset])
			domain += string(rbuf[offset+1:offset+1+l]) + "."
			offset += l + 1
		}
	}
}

func saveToCahce(rbuf []byte) {
	//fmt.Printf("Now cache size is %d\t\t\r", cache.cnt)
	offset := 0
	// Header
	anCount := int(binary.BigEndian.Uint16(rbuf[6:8]))
	offset += 12 // header
	// Request
	domain, i := parseDomain(rbuf[12:], 0)
	offset += i // question
	qtype := binary.BigEndian.Uint16(rbuf[offset : offset+2])
	offset += 4 // type and class
	var k DNSCacheKey
	if qtype == 0x01 {
		k = DNSCacheKey{
			domain: domain,
			v6:     false,
		}
	} else if qtype == 0x1c {
		k = DNSCacheKey{
			domain: domain,
			v6:     true,
		}
	}
	cache.Set(k, parseAnswer(rbuf, offset, anCount), config.CacheExpiry)
	//cache.c.Range(func(key, value any) bool {
	//	keys := key.(DNSCacheKey)
	//	values := value.(DNSCache)
	//	fmt.Println(keys.domain, keys.v6, values.AList)
	//	return true
	//})
}

func parseAnswer(rbuf []byte, offset int, ANCOUNT int) [][]byte {
	var al [][]byte
	for i := 0; i < ANCOUNT; i++ {
		alen := 0
		_, oi := parseDomain(rbuf, offset)
		alen += oi
		rdLength := binary.BigEndian.Uint16(rbuf[offset+alen+8 : offset+alen+10])
		alen += 10
		alen += int(rdLength)
		al = append(al, rbuf[offset:offset+alen])
		offset += alen
	}
	return al
}

func appendToFile(filename string, data string) error {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)

	_, err = f.WriteString(data)
	if err != nil {
		return err
	}
	return nil
}
