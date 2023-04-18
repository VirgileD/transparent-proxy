package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	log "github.com/sirupsen/logrus"
	"github.com/viki-org/dnscache"
	"golang.org/x/net/proxy"
)

var resolver = dnscache.New(time.Minute * 30)
var ipv4RegEx, _ = regexp.Compile(`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`)

func handleConnection(clientConn *net.TCPConn) {
	if clientConn == nil {
		log.Debugf("handleConnection(): oops, clientConn is nil")
		return
	}

	// test if the underlying fd is nil
	remoteAddr := clientConn.RemoteAddr()
	if remoteAddr == nil {
		log.Debugf("handleConnection(): oops, clientConn.fd is nil!")
		return
	}

	ipv4, port, clientConn, err := getOriginalDst(clientConn)
	if err != nil {
		log.Infof("handleConnection(): can not handle this connection, error occurred in getting original destination ip address/port: %+v", err)
		return
	}

	var proxies = ResolveProxy(ipv4, port)
	log.Infof("reloveproxy: %v %v %v", ipv4, port, proxies)
	if proxies == nil {
		handleDirectConnection(clientConn, ipv4, port)
	} else {
		handleProxyConnection(clientConn, ipv4, port)
	}

}

func handleDirectConnection(clientConn *net.TCPConn, ipv4 string, port uint16) {
	if clientConn == nil {
		log.Debugf("handleDirectConnection(): oops, clientConn is nil!")
		return
	}

	// test if the underlying fd is nil
	remoteAddr := clientConn.RemoteAddr()
	if remoteAddr == nil {
		log.Debugf("handleDirectConnection(): oops, clientConn.fd is nil!")
		return
	}

	ipport := fmt.Sprintf("%s:%d", ipv4, port)
	directConn, err := dial(ipport)
	if err != nil {
		clientConnRemoteAddr := "?"
		if clientConn != nil {
			clientConnRemoteAddr = fmt.Sprintf("%v", clientConn.RemoteAddr())
		}
		directConnRemoteAddr := "?"
		if directConn != nil {
			directConnRemoteAddr = fmt.Sprintf("%v", directConn.RemoteAddr())
		}
		log.Infof("DIRECT|%v->%v|Could not connect, giving up: %v", clientConnRemoteAddr, directConnRemoteAddr, err)
		if err = clientConn.Close(); err != nil {
			log.Debugf("handleDirectConnection(): close clientConn error: %v", err)
		}
		return
	}
	log.Debugf("DIRECT|%v->%v|Connected to remote end", clientConn.RemoteAddr(), directConn.RemoteAddr())
	incrDirectConnections()
	go ioCopy(clientConn, directConn, "client", "directserver")
	go ioCopy(directConn, clientConn, "directserver", "client")
}

func handleProxyConnection(clientConn *net.TCPConn, ipv4 string, port uint16) {
	var proxyConn net.Conn
	var err error
	var success bool = false
	var host string
	var headerXFF string = ""

	if clientConn == nil {
		log.Debugf("handleProxyConnection(): oops, clientConn is nil!")
		return
	}

	// test if the underlying fd is nil
	remoteAddr := clientConn.RemoteAddr()
	if remoteAddr == nil {
		log.Debugf("handleProxyConnect(): oops, clientConn.fd is nil!")
		return
	}

	host, _, err = net.SplitHostPort(remoteAddr.String())
	if err == nil {
		headerXFF = fmt.Sprintf("X-Forwarded-For: %s\r\n", host)
	}

	hostname := reverseLookupCache.lookup(ipv4)
	if hostname != "" {
		ipv4 = hostname
	} else {
		names, err := net.LookupAddr(ipv4)
		if err == nil && len(names) > 0 {
			reverseLookupCache.store(ipv4, names[0])
			ipv4 = names[0]
		}
	}

	for _, proxySpec := range ResolveProxy(ipv4, port) {
		log.Debugf("Using proxy %v for %v:%v", proxySpec, ipv4, port)
		// handle socks5 proxy
		if proxySpec.Type == Socks5ProxyType {
			socks5Dial, err := proxy.SOCKS5("tcp", proxySpec.HostPort(), proxySpec.Auth, proxy.Direct)
			if err == nil {
				log.Debugf("PROXY|%v->%v->%s:%d|Connecting via socks5 proxy", clientConn.RemoteAddr(), proxySpec.HostPort(), ipv4, port)
				proxyConn, err = socks5Dial.Dial("tcp", fmt.Sprintf("%s:%d", ipv4, port))
			}
			if err != nil {
				log.Debugf("PROXY|%v->%v->%s:%d|Trying next proxy.", clientConn.RemoteAddr(), proxySpec, ipv4, port)
				continue
			}
			log.Debugf("PROXY|%v->%v->%s:%d|Socks5 proxied connection", clientConn.RemoteAddr(), proxyConn.RemoteAddr(), ipv4, port)
			success = true
			break
		}
		proxyConn, err = dial(proxySpec.HostPort())
		if err != nil {
			log.Debugf("PROXY|%v->%v->%s:%d|Trying next proxy.", clientConn.RemoteAddr(), proxySpec, ipv4, port)
			continue
		}
		log.Debugf("PROXY|%v->%v->%s:%d|Connected to proxy\n", clientConn.RemoteAddr(), proxyConn.RemoteAddr(), ipv4, port)
		var authString = proxySpec.UserInfoBase64()
		if authString != "" {
			authString = fmt.Sprintf("\r\nProxy-Authorization: Basic %s", authString)
		}
		connectString := fmt.Sprintf("CONNECT %s:%d HTTP/1.0%s\r\n%s\r\n", ipv4, port, authString, headerXFF)
		log.Debugf("PROXY|%v->%v->%s:%d|Sending to proxy: %s", clientConn.RemoteAddr(), proxyConn.RemoteAddr(), ipv4, port, strconv.Quote(connectString))
		fmt.Fprint(proxyConn, connectString)
		status, err := bufio.NewReader(proxyConn).ReadString('\n')
		log.Debugf("PROXY|%v->%v->%s:%d|Received from proxy: %s", clientConn.RemoteAddr(), proxyConn.RemoteAddr(), ipv4, port, strconv.Quote(status))
		if err != nil {
			log.Infof("PROXY|%v->%v->%s:%d|ERR: Could not find response to CONNECT: err=%v. Trying next proxy", clientConn.RemoteAddr(), proxyConn.RemoteAddr(), ipv4, port, err)
			incrProxyNoConnectResponses()
			continue
		}
		if strings.Contains(status, "400") { // bad request
			log.Debugf("PROXY|%v->%v->%s:%d|Status from proxy=400 (Bad Request)", clientConn.RemoteAddr(), proxyConn.RemoteAddr(), ipv4, port)
			log.Debugf("%v: Response from proxy=400", proxySpec)
			incrProxy400Responses()
			ioCopy(clientConn, proxyConn, "client", "proxyserver")
			return
		}
		if strings.Contains(status, "301") || strings.Contains(status, "302") && cfg.RelayingRedirectResponse {
			log.Debugf("PROXY|%v->%v->%s:%d|Status from proxy=%s (Redirect), relaying response to client", clientConn.RemoteAddr(), proxyConn.RemoteAddr(), ipv4, port, strconv.Quote(status))
			incrProxy300Responses()
			fmt.Fprint(clientConn, status)
			ioCopy(clientConn, proxyConn, "client", "proxyserver")
			return
		}
		if strings.Contains(status, "200") {
			log.Infof("PROXY|%v->%v->%s:%d|ERR: Proxy response to CONNECT was: %s. Trying next proxy.\n", clientConn.RemoteAddr(), proxyConn.RemoteAddr(), ipv4, port, strconv.Quote(status))
			incrProxyNon200Responses()
			continue
		} else {
			incrProxy200Responses()
		}
		log.Debugf("PROXY|%v->%v->%s:%d|Proxied connection", clientConn.RemoteAddr(), proxyConn.RemoteAddr(), ipv4, port)
		success = true
		break
	}
	if proxyConn == nil {
		log.Warningf("handleProxyConnection(): oops, proxyConn is nil!")
		return
	}
	if !success {
		log.Infof("PROXY|%v->UNAVAILABLE->%s:%d|ERR: Tried all proxies, but could not establish connection. Giving up.", clientConn.RemoteAddr(), ipv4, port)
		fmt.Fprint(clientConn, "HTTP/1.0 503 Service Unavailable\r\nServer: go-any-proxy\r\nX-AnyProxy-Error: ERR_NO_PROXIES\r\n\r\n")
		clientConn.Close()
		return
	}
	incrProxiedConnections()
	go ioCopy(clientConn, proxyConn, "client", "proxyserver")
	go ioCopy(proxyConn, clientConn, "proxyserver", "client")
}

func ResolveProxy(ipv4 string, port uint16) []*Proxy {
	var hostname *string = nil
	// iterating pairs from oldest to newest rule:
	for rule := rules.Oldest(); rule != nil; rule = rule.Next() {
		log.Warningf("ResolveProxy(): testing rule %v", rule.Key)
		//fmt.Printf("%s => %s\n", pair.Key, pair.Value)
		for _, destination := range rule.Value.destinations {
			log.Warningf("ResolveProxy(): testing rule %v destination %v (%v / %v /%v)", rule.Key, destination, isDomain(destination), isCIDR(destination), "dest is IP")
			// IP
			if isIPV4(destination) && destination == ipv4 {
				log.Debugf("resolve proxy by IP %v:%v: %v", ipv4, port, rule.Key)
				return rule.Value.proxies
			} else if isCIDR(destination) {
				_, directorIpNet, err := net.ParseCIDR(destination)
				if err != nil {
					panic(fmt.Sprintf("Unable to parse CIDR string : %s : %s\n", destination, err))
				}
				if directorIpNet.Contains(net.ParseIP(ipv4)) {
					log.Debugf("resolve proxy by IP net %v(%v:%v): %v", directorIpNet, ipv4, port, rule.Key)
					return rule.Value.proxies
				}
			} else if isDomain(destination) {
				re, err := regexp.Compile(destination)
				if err != nil {
					panic(fmt.Sprintf("Unnable to parse pattern %v", rule))
				}
				if hostname == nil {
					h := GetHostName(ipv4)
					hostname = &h
				}
				if *hostname == "" {
					continue
				}
				*hostname = strings.TrimSuffix(*hostname, ".")
				if re.MatchString(*hostname) {
					log.Debugf("resolve proxy by domain %v(%v:%v): %v", *hostname, ipv4, port, rule.Key)
					return rule.Value.proxies
				}
			}
		}
	}
	/*var hostname *string = nil
	for _, cpr := range rules {
		proxy, err := ParseProxy(cpr.Proxy)
			if err != nil {
				panic(err)
			}
			proxy.Type = cpr.Type
			for _, rule := range cpr.Rules {
			}
		}
	}
	return defaultProxyList*/
	return nil
}

func isDomain(rule string) bool {
	return strings.IndexFunc(rule, func(r rune) bool {
		return unicode.IsLetter(r)
	}) != -1
}

func isCIDR(rule string) bool {
	return strings.Contains(rule, "/")
}

func isIPV4(rule string) bool {
	return ipv4RegEx.MatchString(rule)
}

func getOriginalDst(clientConn *net.TCPConn) (ipv4 string, port uint16, newTCPConn *net.TCPConn, err error) {
	if clientConn == nil {
		log.Debugf("copy(): oops, dst is nil!")
		err = errors.New("ERR: clientConn is nil")
		return
	}

	// test if the underlying fd is nil
	remoteAddr := clientConn.RemoteAddr()
	if remoteAddr == nil {
		log.Debugf("getOriginalDst(): oops, clientConn.fd is nil!")
		err = errors.New("ERR: clientConn.fd is nil")
		return
	}

	srcipport := fmt.Sprintf("%v", clientConn.RemoteAddr())

	// Use reflect to get internal sysfd
	rawClientConn := reflect.ValueOf(clientConn).Elem()
	rawFd := rawClientConn.FieldByName("fd").Elem()
	valuePfd := rawFd.FieldByName("pfd")
	var rawSysFd int64
	if valuePfd.IsValid() {
		// go1.9
		rawSysFd = valuePfd.FieldByName("Sysfd").Int()
	} else {
		// < go1.9
		rawSysFd = rawFd.FieldByName("sysfd").Int()
	}
	// Get original destination
	// this is the only syscall in the Golang libs that I can find that returns 16 bytes
	// Example result: &{Multiaddr:[2 0 31 144 206 190 36 45 0 0 0 0 0 0 0 0] Interface:0}
	// port starts at the 3rd byte and is 2 bytes long (31 144 = port 8080)
	// IPv4 address starts at the 5th byte, 4 bytes long (206 190 36 45)
	addr, err := syscall.GetsockoptIPv6Mreq(int(rawSysFd), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
	if err != nil {
		log.Infof("GETORIGINALDST|%v->?->FAILEDTOBEDETERMINED|ERR: getsocketopt(SO_ORIGINAL_DST) failed: %v", srcipport, err)
		return
	}
	log.Debugf("getOriginalDst(): SO_ORIGINAL_DST=%+v", addr)
	newTCPConn = clientConn

	ipv4 = itod(uint(addr.Multiaddr[4])) + "." +
		itod(uint(addr.Multiaddr[5])) + "." +
		itod(uint(addr.Multiaddr[6])) + "." +
		itod(uint(addr.Multiaddr[7]))
	port = uint16(addr.Multiaddr[2])<<8 + uint16(addr.Multiaddr[3])

	return
}

// from pkg/net/parse.go
// Convert i to decimal string.
func itod(i uint) string {
	if i == 0 {
		return "0"
	}

	// Assemble decimal in reverse order.
	var b [32]byte
	bp := len(b)
	for ; i > 0; i /= 10 {
		bp--
		b[bp] = byte(i%10) + '0'
	}

	return string(b[bp:])
}

func ioCopy(dst net.Conn, src net.Conn, dstname string, srcname string) {
	if dst == nil {
		log.Debugf("copy(): oops, dst is nil!")
		return
	}
	if src == nil {
		log.Debugf("copy(): oops, src is nil!")
		return
	}
	copied, err := io.Copy(dst, src)
	if err != nil {
		if operr, ok := err.(*net.OpError); ok {
			if strings.Contains(operr.Err.Error(), "use of closed network connection") {
				log.Debugf("copy(): CLOSED %s(%v)->%s(%v): Copied=%v", srcname, src.RemoteAddr(), dstname, dst.RemoteAddr(), copied)
			} else {
				log.Debugf("copy(): ERROR  %s(%v)->%s(%v): Op=%s, Net=%s, Err=%v, Copied=%v", srcname, src.RemoteAddr(), dstname, dst.RemoteAddr(), operr.Op, operr.Net, operr.Err, copied)
			}
			if strings.HasPrefix(operr.Op, "read") {
				if srcname == "proxyserver" {
					incrProxyServerReadErr()
				}
				if srcname == "directserver" {
					incrDirectServerReadErr()
				}
			}
			if strings.HasPrefix(operr.Op, "write") {
				if srcname == "proxyserver" {
					incrProxyServerWriteErr()
				}
				if srcname == "directserver" {
					incrDirectServerWriteErr()
				}
			}
		} else {
			log.Debugf("copy(): ERROR  %s(%v)->%s(%v): Err=%v, Copied=%v", srcname, src.RemoteAddr(), dstname, dst.RemoteAddr(), err, copied)
		}
	} else {
		log.Debugf("copy(): DONE   %s(%v)->%s(%v): Copied=%v", srcname, src.RemoteAddr(), dstname, dst.RemoteAddr(), copied)
	}
	dst.Close()
	src.Close()
}

func dial(spec string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(spec)
	if err != nil {
		log.Infof("dial(): ERR: could not extract host and port from spec %v: %v", spec, err)
		return nil, err
	}
	remoteIP := net.ParseIP(host)
	if remoteIP == nil {
		remoteIP, err = resolver.FetchOne(host)
		if err != nil {
			log.Infof("dial(): ERR: could not resolve %v: %v", host, err)
			return nil, err
		}
	}
	portInt, err := strconv.Atoi(port)
	if err != nil {
		log.Infof("dial(): ERR: could not convert network port from string \"%s\" to integer: %v", port, err)
		return nil, err
	}
	remoteAddrAndPort := &net.TCPAddr{IP: remoteIP, Port: portInt}
	sa := netAddrToSockaddr(remoteAddrAndPort)
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		log.Infof("dial(): ERR: could not create socket: %v", err)
		return nil, err
	}
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, cfg.IpTableMark)
	if err != nil {
		log.Debugf("dial(): ERR: could not set sockopt with mark %v: %v", cfg.IpTableMark, err)
		syscall.Close(fd)
		return nil, err
	}
	err = syscall.Connect(fd, sa)
	if err != nil {
		log.Infof("dial(): ERR: could not connect to %v:%v: %v", remoteIP, portInt, err)
		syscall.Close(fd)
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "")
	conn, err := net.FileConn(file)
	// duplicate file created need to close
	if closeErr := file.Close(); closeErr != nil {
		log.Errorf("dial(): ERR: cannot close file %v: %v", fd, closeErr)
	}
	if err != nil {
		log.Infof("dial(): ERR: could not create connection with fd %v: %v", fd, err)
		return nil, err
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		return tcpConn, err
	}
	return nil, errors.New("invalid connection type")
}

// netAddrToSockaddr converts a net.Addr to a syscall.Sockaddr.
// Returns nil if the input is invalid or conversion is not possible.
func netAddrToSockaddr(addr net.Addr) syscall.Sockaddr {
	switch addr := addr.(type) {
	case *net.TCPAddr:
		return tcpAddrToSockaddr(addr)
	default:
		return nil
	}
}

// tcpAddrToSockaddr converts a net.TCPAddr to a syscall.Sockaddr.
// Returns nil if conversion fails.
func tcpAddrToSockaddr(addr *net.TCPAddr) syscall.Sockaddr {
	sa := ipAndZoneToSockaddr(addr.IP, addr.Zone)
	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		sa.Port = addr.Port
		return sa
	case *syscall.SockaddrInet6:
		sa.Port = addr.Port
		return sa
	default:
		return nil
	}
}
