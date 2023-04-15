//
// any_proxy.go - Transparently proxy a connection using Linux iptables REDIRECT
//
// Copyright (C) 2013 Ryan A. Chapman. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//   1. Redistributions of source code must retain the above copyright notice,
//      this list of conditions and the following disclaimer.
//
//   2. Redistributions in binary form must reproduce the above copyright notice,
//      this list of conditions and the following disclaimer in the documentation
//      and/or other materials provided with the distribution.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS
// OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
// OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//
//
// Tested to 2000 connections/second.  If you turn off logging, you can get 10,000/sec. So logging needs
// to be changed to nonblocking one day.
//
// TODO:
// add num of connected clients to stats
// add ability to print details of each connected client (src,dst,proxy or direct addr) to stats
//
// Ryan A. Chapman, ryan@rchapman.org
// Sun Apr  7 21:04:34 MDT 2013
//

package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"reflect"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/emirpasic/gods/sets/hashset"
	log "github.com/feng-zh/go-any-proxy/internal/flogger"
	"github.com/viki-org/dnscache"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/proxy"
)

const VERSION = "1.2"
const SO_ORIGINAL_DST = 80
const DEFAULTLOG = "/var/log/any_proxy.log"
const STATSFILE = "/var/log/any_proxy.stats"

var gListenAddrPort string
var gProxyServerSpec string
var gDirects string
var gVerbosity int
var gSkipCheckUpstreamsReachable int
var gProxyServers []*Proxy
var gLogfile string
var gCpuProfile string
var gMemProfile string
var gClientRedirects int
var gReverseLookups int
var gIpTableMark int
var gDnsListenAddrPort string
var gProxyConfigFile string
var gProxyPorts string
var gDiscoverDirects bool

type cacheEntry struct {
	hostname string
	expires  time.Time
}
type reverseLookupCache struct {
	hostnames sync.Map
	keys      []string
	next      int
}

func NewReverseLookupCache() *reverseLookupCache {
	return &reverseLookupCache{
		keys: make([]string, 65536),
	}
}
func (c *reverseLookupCache) lookup(ipv4 string) string {
	hit, ok := c.hostnames.Load(ipv4)
	if !ok {
		log.Debugf("lookup(): CACHE_MISS")
		return ""
	}
	if hit, ok := hit.(*cacheEntry); ok {
		if hit.expires.After(time.Now()) {
			return hit.hostname
		} else {
			log.Debugf("lookup(): CACHE_EXPIRED")
			c.hostnames.Delete(ipv4)
		}
	}
	return ""
}

func (c *reverseLookupCache) store(ipv4, hostname string) {
	c.storeTtl(ipv4, hostname, int(time.Hour/time.Second))
}

func (c *reverseLookupCache) storeTtl(ipv4, hostname string, ttl int) {
	c.hostnames.Delete(c.keys[c.next])
	c.keys[c.next] = ipv4
	c.next = (c.next + 1) & 65535
	c.hostnames.Store(ipv4, &cacheEntry{hostname: hostname, expires: time.Now().Add(time.Duration(ttl) * time.Second)})
}

func ListHostNames() map[string]string {
	c := gReverseLookupCache
	m := make(map[string]string)
	c.hostnames.Range(func(ipv4, entry interface{}) bool {
		m[entry.(*cacheEntry).hostname] = ipv4.(string)
		return true
	})
	return m
}

func GetHostName(ip string) string {
	hostname := gReverseLookupCache.lookup(ip)
	return hostname
}

var gReverseLookupCache = NewReverseLookupCache()

type directorFunc func(*net.IP) bool

var director func(*net.IP) (bool, int)

var proxyResolver = func(ipv4 string, port uint16, defaultProxyList []*Proxy) []*Proxy {
	return defaultProxyList
}

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stdout, "%s\n\n", versionString())
		fmt.Fprintf(os.Stdout, "usage: %s -l listenaddress -p proxies [-d directs] [-v=N] [-f file] [-c file] [-m file] [-k mark]\n", os.Args[0])
		fmt.Fprintf(os.Stdout, "       Proxies any tcp port transparently using Linux netfilter\n\n")
		fmt.Fprintf(os.Stdout, "Mandatory\n")
		fmt.Fprintf(os.Stdout, "  -l=ADDRPORT      Address and port to listen on (e.g., :3128 or 127.0.0.1:3128)\n")
		fmt.Fprintf(os.Stdout, "Optional\n")
		fmt.Fprintf(os.Stdout, "  -c=FILE          Write a CPU profile to FILE. The pprof program, which is part of Golang's\n")
		fmt.Fprintf(os.Stdout, "                   standard pacakge, can be used to interpret the results. You can invoke pprof\n")
		fmt.Fprintf(os.Stdout, "                   with \"go tool pprof\"\n")
		fmt.Fprintf(os.Stdout, "  -d=DIRECTS       List of IP addresses that the proxy should send to directly instead of\n")
		fmt.Fprintf(os.Stdout, "                   to the upstream proxies (e.g., -d 10.1.1.1,10.1.1.2)\n")
		fmt.Fprintf(os.Stdout, "  -f=FILE          Log file. If not specified, defaults to %s\n", DEFAULTLOG)
		fmt.Fprintf(os.Stdout, "  -h               This usage message\n")
		fmt.Fprintf(os.Stdout, "  -k=MARK          The iptable mark value to pass through in case of loop proxy\n")
		fmt.Fprintf(os.Stdout, "  -m=FILE          Write a memory profile to FILE. This file can also be interpreted by golang's pprof\n\n")
		fmt.Fprintf(os.Stdout, "  -p=PROXIES       Address and ports of upstream proxy servers to use\n")
		fmt.Fprintf(os.Stdout, "                   Multiple address/ports can be specified by separating with commas\n")
		fmt.Fprintf(os.Stdout, "                   (e.g., 10.1.1.1:80,10.2.2.2:3128 would try to proxy requests to a\n")
		fmt.Fprintf(os.Stdout, "                    server listening on port 80 at 10.1.1.1 and if that failed, would\n")
		fmt.Fprintf(os.Stdout, "                    then try port 3128 at 10.2.2.2)\n")
		fmt.Fprintf(os.Stdout, "                   Note that requests are not load balanced. If a request fails to the\n")
		fmt.Fprintf(os.Stdout, "                   first proxy, then the second is tried and so on.\n\n")
		fmt.Fprintf(os.Stdout, "  -r=1             Enable relaying of HTTP redirects from upstream to clients\n")
		fmt.Fprintf(os.Stdout, "  -R=1             Enable reverse lookups of destination IP address and use hostname in CONNECT\n")
		fmt.Fprintf(os.Stdout, "                   request instead of the numeric IP if available. A local DNS server could be\n")
		fmt.Fprintf(os.Stdout, "                   configured to provide a reverse lookup of the forward lookup responses seen.\n")
		fmt.Fprintf(os.Stdout, "  -s=1             Skip checking if upstream proxy servers are reachable on startup.\n")
		fmt.Fprintf(os.Stdout, "  -v=1             Print debug information to logfile %s\n", DEFAULTLOG)
		fmt.Fprintf(os.Stdout, "any_proxy should be able to achieve 2000 connections/sec with logging on, 10k with logging off (-f=/dev/null).\n")
		fmt.Fprintf(os.Stdout, "Before starting any_proxy, be sure to change the number of available file handles to at least 65535\n")
		fmt.Fprintf(os.Stdout, "with \"ulimit -n 65535\"\n")
		fmt.Fprintf(os.Stdout, "Some other tunables that enable higher performance:\n")
		fmt.Fprintf(os.Stdout, "  net.core.netdev_max_backlog = 2048\n")
		fmt.Fprintf(os.Stdout, "  net.core.somaxconn = 1024\n")
		fmt.Fprintf(os.Stdout, "  net.core.rmem_default = 8388608\n")
		fmt.Fprintf(os.Stdout, "  net.core.rmem_max = 16777216\n")
		fmt.Fprintf(os.Stdout, "  net.core.wmem_max = 16777216\n")
		fmt.Fprintf(os.Stdout, "  net.ipv4.ip_local_port_range = 2000 65000\n")
		fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_window_scaling = 1\n")
		fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_max_syn_backlog = 3240000\n")
		fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_max_tw_buckets = 1440000\n")
		fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_mem = 50576 64768 98152\n")
		fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_rmem = 4096 87380 16777216\n")
		fmt.Fprintf(os.Stdout, "  NOTE: if you see syn flood warnings in your logs, you need to adjust tcp_max_syn_backlog, tcp_synack_retries and tcp_abort_on_overflow\n")
		fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_syncookies = 1\n")
		fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_wmem = 4096 65536 16777216\n")
		fmt.Fprintf(os.Stdout, "  net.ipv4.tcp_congestion_control = cubic\n\n")
		fmt.Fprintf(os.Stdout, "To obtain statistics, send any_proxy signal SIGUSR1. Current stats will be printed to %v\n", STATSFILE)
		fmt.Fprintf(os.Stdout, "Report bugs to <ryan@rchapman.org>.\n")
	}
	flag.StringVar(&gCpuProfile, "c", "", "Write cpu profile to file")
	flag.StringVar(&gDirects, "d", "", "IP addresses to go direct")
	flag.StringVar(&gLogfile, "f", "", "Log file")
	flag.StringVar(&gListenAddrPort, "l", "", "Address and port to listen on")
	flag.StringVar(&gMemProfile, "m", "", "Write mem profile to file")
	flag.StringVar(&gProxyServerSpec, "p", "", "Proxy servers to use, separated by commas. E.g. -p proxy1.tld.com:80,proxy2.tld.com:8080,proxy3.tld.com:80")
	flag.IntVar(&gClientRedirects, "r", 0, "Should we relay HTTP redirects from upstream proxies? -r=1 if we should.\n")
	flag.IntVar(&gReverseLookups, "R", 0, "Should we perform reverse lookups of destination IPs and use hostnames? -R=1 if we should.\n")
	flag.IntVar(&gSkipCheckUpstreamsReachable, "s", 0, "On startup, should we check if the upstreams are available? -s=0 means we should and if one is found to be not reachable, then remove it from the upstream list.\n")
	flag.IntVar(&gVerbosity, "v", 0, "Control level of logging. v=1 results in debugging info printed to the log.\n")
	flag.IntVar(&gIpTableMark, "k", 5, "Mark value set in proxy stream, default is 5.\n")
	flag.StringVar(&gDnsListenAddrPort, "dns", "", "Address and port for DNS Proxy to intercept name resolving.\n")
	flag.StringVar(&gProxyConfigFile, "pf", "", "Additional proxy configuration file for advanced proxy routing.\n")
	flag.StringVar(&gProxyPorts, "ports", "", "Proxy Ports used for internal iptables. If not specified use external iptables utility to setup.\n")
	flag.BoolVar(&gDiscoverDirects, "dd", false, "Discover additional IP addresses to go direct")

	director = getDirector(nil)
}

func versionString() (v string) {
	buildNum := strings.ToUpper(strconv.FormatInt(BUILDTIMESTAMP, 36))
	buildDate := time.Unix(BUILDTIMESTAMP, 0).Format(time.UnixDate)
	goVersion := runtime.Version()
	v = fmt.Sprintf("any_proxy %s (build %v, %v by %v@%v) - %s", VERSION, buildNum, buildDate, BUILDUSER, BUILDHOST, goVersion)
	return
}

func buildDirectors(directs string, discoverDirects bool) (string, []directorFunc) {
	// Generates a list of directorFuncs that are have "cached" values within
	// the scope of the functions.

	if discoverDirects {
		discoverDirects, err := autoDiscoverDirects()
		if err != nil {
			panic(fmt.Sprintf("Unable to discover additional IP addresses to go direct: %v", err))
		}
		if directs != "" {
			directs = fmt.Sprintf("%s,%s", discoverDirects, directs)
		} else {
			directs = discoverDirects
		}
	}
	directorCidrs := strings.Split(directs, ",")
	log.Infof("Use director IP address: %v", directorCidrs)
	directorFuncs := make([]directorFunc, len(directorCidrs))

	for idx, directorCidr := range directorCidrs {
		//dstring := director
		var dfunc directorFunc
		if strings.Contains(directorCidr, "/") {
			_, directorIpNet, err := net.ParseCIDR(directorCidr)
			if err != nil {
				panic(fmt.Sprintf("\nUnable to parse CIDR string : %s : %s\n", directorCidr, err))
			}
			dfunc = func(ptestip *net.IP) bool {
				testIp := *ptestip
				return directorIpNet.Contains(testIp)
			}
			directorFuncs[idx] = dfunc
		} else {
			var directorIp net.IP = net.ParseIP(directorCidr)
			dfunc = func(ptestip *net.IP) bool {
				var testIp net.IP = *ptestip
				return testIp.Equal(directorIp)
			}
			directorFuncs[idx] = dfunc
		}

	}
	return directs, directorFuncs
}

func getDirector(directors []directorFunc) func(*net.IP) (bool, int) {
	// getDirector:
	// Returns a function(directorFunc) that loops through internally held
	// directors evaluating each for possible matches.
	//
	// directorFunc:
	// Loops through directors and returns the (true, idx) where the index is
	// the sequential director that returned true. Else the function returns
	// (false, 0) if there are no directors to handle the ip.

	dFunc := func(ipaddr *net.IP) (bool, int) {
		for idx, dfunc := range directors {
			if dfunc(ipaddr) {
				return true, idx
			}
		}
		return false, 0
	}
	return dFunc
}

func setupProfiling() {
	// Make sure we have enough time to write profile's to disk, even if user presses Ctrl-C
	if gMemProfile == "" || gCpuProfile == "" {
		return
	}

	var profilef *os.File
	var err error
	if gMemProfile != "" {
		profilef, err = os.Create(gMemProfile)
		if err != nil {
			panic(err)
		}
	}

	if gCpuProfile != "" {
		f, err := os.Create(gCpuProfile)
		if err != nil {
			panic(err)
		}
		pprof.StartCPUProfile(f)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			if gCpuProfile != "" {
				pprof.StopCPUProfile()
			}
			if gMemProfile != "" {
				pprof.WriteHeapProfile(profilef)
				profilef.Close()
			}
			time.Sleep(5000 * time.Millisecond)
			os.Exit(0)
		}
	}()
}

func setupLogging() {
	if gLogfile == "" {
		gLogfile = DEFAULTLOG
	}

	log.SetLevel(log.INFO)
	if gVerbosity != 0 {
		log.SetLevel(log.DEBUG)
	}

	if err := log.OpenFile(gLogfile, log.FLOG_APPEND, 0644); err != nil {
		log.Fatalf("Unable to open log file : %s", err)
	}
}

func main() {
	flag.Parse()
	if gListenAddrPort == "" {
		flag.Usage()
		os.Exit(1)
	}

	runtime.GOMAXPROCS(runtime.NumCPU() / 2)
	setupLogging()
	setupProfiling()
	setupStats()
	setupStackDump()

	directs, dirFuncs := buildDirectors(gDirects, gDiscoverDirects)

	if gProxyConfigFile != "" {
		file, err := os.Open(gProxyConfigFile)
		if err != nil {
			panic(err)
		}
		log.Infof("Using proxy config file :%v", gProxyConfigFile)
		proxyConfig := NewProxyConfig(file)
		if err := file.Close(); err != nil {
			panic(err)
		}
		proxyResolver = proxyConfig.ResolveProxy
		dirFuncs = append(dirFuncs, proxyConfig.DirectorFunc(false)...)
	}

	director = getDirector(dirFuncs)

	log.RedirectStreams()

	if gDnsListenAddrPort != "" {
		dp := NewDnsProxy(gDnsListenAddrPort, "")
		if err := dp.ListenAndServe(false); err != nil {
			log.Warningf("Error open dns proxy on %v: %v", gDnsListenAddrPort, err)
		}
		defer dp.Close()
		log.Infof("Listening DNS proxy on %v", gDnsListenAddrPort)
	}

	// if user gave us upstream proxies, check and see if they are alive
	if gProxyServerSpec != "" {
		checkProxies()
	}

	lnaddr, err := net.ResolveTCPAddr("tcp", gListenAddrPort)
	if err != nil {
		panic(err)
	}

	listener, err := net.ListenTCP("tcp", lnaddr)
	if err != nil {
		panic(err)
	}

	closer := new(sync.Once)
	defer closer.Do(func() {
		_ = listener.Close()
	})

	log.Infof("Listening for connections on %v\n", listener.Addr())

	// start iptables if enabled
	if gProxyPorts != "" {
		var listenPort int
		var lnaddr *net.TCPAddr
		if lnaddr, err = net.ResolveTCPAddr("tcp", gListenAddrPort); err != nil {
			panic(err)
		} else {
			listenPort = lnaddr.Port
		}
		ipTableHandler, err := InstallIPTables(directs, gProxyPorts, listenPort, gIpTableMark)
		if err != nil {
			panic(err)
		}
		log.Infof("Installed iptables for ports %v", gProxyPorts)

		defer func() {
			err := ipTableHandler.Uninstall()
			log.Infof("Uninstalled iptables for ports %v", ipTableHandler.proxyPorts)
			if err != nil {
				log.Warningf("Got error during uninstall iptables: %v", err)
			}
		}()
	}

	// install stop handler
	stopped := false
	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
		stopped = true
		closer.Do(func() {
			_ = listener.Close()
		})
	}()

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			if stopped {
				log.Infof("Stopping Listening")
				break
			}
			log.Infof("Error accepting connection: %v\n", err)
			incrAcceptErrors()
			continue
		}
		incrAcceptSuccesses()
		log.Debugf("main(): Get new connection:%+v\n", conn.RemoteAddr())
		go handleConnection(conn)
	}
}

func checkProxies() {
	var err error
	gProxyServers, err = ParseProxyList(gProxyServerSpec)
	if err != nil {
		log.Errorf("Invalid proxy list: %s", err)
		msg := "Parse proxy list failure. Exiting."
		log.Infof("%s\n", msg)
		fmt.Fprint(os.Stderr, msg)
		os.Exit(1)
	}
	// make sure proxies resolve and are listening on specified port, unless -s=1, then don't check for reachability
	for i, proxySpec := range gProxyServers {
		log.Infof("Added proxy server %v\n", proxySpec)
		if gSkipCheckUpstreamsReachable != 1 {
			conn, err := dial(proxySpec.HostPort())
			if err != nil {
				log.Infof("Test connection to %v: failed. Removing from proxy server list\n", proxySpec)
				a := gProxyServers[:i]
				b := gProxyServers[i+1:]
				gProxyServers = append(a, b...)
				continue
			}
			conn.Close()
		}
	}
	// do we have at least one proxy server?
	if len(gProxyServers) == 0 {
		msg := "None of the proxy servers specified are available. Exiting."
		log.Infof("%s\n", msg)
		fmt.Fprint(os.Stderr, msg)
		os.Exit(1)
	}
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
	log.Debugf("getOriginalDst(): SO_ORIGINAL_DST=%+v\n", addr)
	newTCPConn = clientConn

	ipv4 = itod(uint(addr.Multiaddr[4])) + "." +
		itod(uint(addr.Multiaddr[5])) + "." +
		itod(uint(addr.Multiaddr[6])) + "." +
		itod(uint(addr.Multiaddr[7]))
	port = uint16(addr.Multiaddr[2])<<8 + uint16(addr.Multiaddr[3])

	return
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

// ipAndZoneToSockaddr converts a net.IP (with optional IPv6 Zone) to a syscall.Sockaddr
// Returns nil if conversion fails.
func ipAndZoneToSockaddr(ip net.IP, zone string) syscall.Sockaddr {
	switch {
	case len(ip) < net.IPv4len: // default to IPv4
		buf := [4]byte{0, 0, 0, 0}
		return &syscall.SockaddrInet4{Addr: buf}

	case ip.To4() != nil:
		var buf [4]byte
		ip4 := ip.To4()
		copy(buf[:], ip4) // last 4 bytes
		return &syscall.SockaddrInet4{Addr: buf}
	}
	panic("should be unreachable")
}

var resolver = dnscache.New(time.Minute * 30)

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
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, gIpTableMark)
	if err != nil {
		log.Debugf("dial(): ERR: could not set sockopt with mark %v: %v", gIpTableMark, err)
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

	if gReverseLookups == 1 {
		hostname := gReverseLookupCache.lookup(ipv4)
		if hostname != "" {
			ipv4 = hostname
		} else {
			names, err := net.LookupAddr(ipv4)
			if err == nil && len(names) > 0 {
				gReverseLookupCache.store(ipv4, names[0])
				ipv4 = names[0]
			}
		}
	}

	for _, proxySpec := range proxyResolver(ipv4, port, gProxyServers) {
		log.Debugf("Using proxy %v for %v:%v", proxySpec, ipv4, port)
		// handle socks5 proxy
		if proxySpec.Type == Socks5ProxyType {
			socks5Dial, err := proxy.SOCKS5("tcp", proxySpec.HostPort(), proxySpec.Auth, proxy.Direct)
			if err == nil {
				log.Debugf("PROXY|%v->%v->%s:%d|Connecting via socks5 proxy\n", clientConn.RemoteAddr(), proxySpec.HostPort(), ipv4, port)
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
		log.Debugf("PROXY|%v->%v->%s:%d|Sending to proxy: %s\n", clientConn.RemoteAddr(), proxyConn.RemoteAddr(), ipv4, port, strconv.Quote(connectString))
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
		if strings.Contains(status, "301") || strings.Contains(status, "302") && gClientRedirects == 1 {
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
		log.Infof("PROXY|%v->UNAVAILABLE->%s:%d|ERR: Tried all proxies, but could not establish connection. Giving up.\n", clientConn.RemoteAddr(), ipv4, port)
		fmt.Fprint(clientConn, "HTTP/1.0 503 Service Unavailable\r\nServer: go-any-proxy\r\nX-AnyProxy-Error: ERR_NO_PROXIES\r\n\r\n")
		clientConn.Close()
		return
	}
	incrProxiedConnections()
	go ioCopy(clientConn, proxyConn, "client", "proxyserver")
	go ioCopy(proxyConn, clientConn, "proxyserver", "client")
}

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
		log.Infof("handleConnection(): can not handle this connection, error occurred in getting original destination ip address/port: %+v\n", err)
		return
	}
	// If no upstream proxies were provided on the command line, assume all traffic should be sent directly
	if gProxyServerSpec == "" {
		handleDirectConnection(clientConn, ipv4, port)
		return
	}
	// Evaluate for direct connection
	ip := net.ParseIP(ipv4)
	if ok, _ := director(&ip); ok {
		handleDirectConnection(clientConn, ipv4, port)
		return
	}
	handleProxyConnection(clientConn, ipv4, port)
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

func autoDiscoverDirects() (string, error) {
	if routes, err := netlink.RouteList(nil, netlink.FAMILY_V4); err != nil {
		return "", err
	} else {
		set := hashset.New()
		// default private noProxy
		set.Add("127.0.0.1/8", "192.168.0.1/16", "172.16.0.0/12")
		for _, route := range routes {
			if route.Dst != nil && route.Src != nil {
				set.Add(route.Dst.String())
			}
		}
		var items []string
		for _, k := range set.Values() {
			items = append(items, fmt.Sprintf("%s", k))
		}
		sort.Strings(items)
		return strings.Join(items, ","), nil
	}
}
