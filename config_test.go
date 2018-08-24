package main

import (
	"testing"
	"strings"
	"github.com/stretchr/testify/assert"
	"net"
)

var data = `
---
proxy:
rules:
  - 10.0.0.0/8
  - 192.168.0.0/16
  - '*.example.net'
---
proxy: proxy1.example.com:8080
rules:
  - '172.168.1.0/16'
  - '*.example.com'
  - '*.example.*'
---
proxy: proxy2.example.com:8080
rules:
  - '*.net'
---
proxy: proxy3.example.com:1080
type: socks5
rules:
  - '*.io'
`

var proxy1, _ = ParseProxy("proxy1.example.com:8080")
var proxy2, _ = ParseProxy("proxy2.example.com:8080")
var proxy3, _ = ParseProxy("socks5://proxy3.example.com:1080")

var expectedData = [...]ProxyRule{
	{Rules: []string{"10.0.0.0/8", "192.168.0.0/16", "*.example.net"}},
	{Proxy: proxy1.HostPort(), Type: proxy1.Type, Rules: []string{"172.168.1.0/16", "*.example.com", "*.example.*"}},
	{Proxy: proxy2.HostPort(), Type: proxy2.Type, Rules: []string{"*.net"}},
	{Proxy: proxy3.HostPort(), Type: proxy3.Type, Rules: []string{"*.io"}},
}

func TestProxyConfig_UnmarshalProxyRules(t *testing.T) {
	config := NewProxyConfig(strings.NewReader(data))
	assert.Len(t, config.proxyRules, len(expectedData))
	for i, d := range expectedData {
		assert.Equal(t, d, config.proxyRules[i])
	}
}

func TestProxyConfig_DirectorFunc(t *testing.T) {
	config := NewProxyConfig(strings.NewReader(data))
	directorFuncs := config.DirectorFunc(true)
	assert.Len(t, directorFuncs, 3)
	all := func(ip *net.IP) bool {
		for _, f := range directorFuncs {
			if f(ip) {
				return true
			}
		}
		return false
	}
	fakeHosts := map[string]string{
		"12.12.12.12": "noproxy.example.net",
		"10.1.2.3":    "www.example.net",
		"13.12.12.12": "www.example.com",
	}
	findHostName = func(ip string) string {
		return fakeHosts[ip]
	}
	results := map[string]bool{
		"12.12.12.12": true,  // in hosts, *.example.net
		"10.1.2.3":    true,  // in 10.0.0.0/8
		"13.12.12.12": false, // no proxy
		"10.2.2.3":    true,  // in 10.0.0.0/8
		"192.1.1.1":   false, // not in 192.168.0.0/16
		"192.168.1.1": true,  // in 192.168.0.0/16
	}
	for k, v := range results {
		ip := net.ParseIP(k)
		assert.Equalf(t, v, all(&ip), "ip director for %v?", k)
	}
}

func TestProxyConfig_DirectorFunc_All(t *testing.T) {
	config := NewProxyConfig(strings.NewReader(data))
	directorFuncs := config.DirectorFunc(false)
	assert.Len(t, directorFuncs, 1)
	all := func(ip *net.IP) bool {
		for _, f := range directorFuncs {
			if f(ip) {
				return true
			}
		}
		return false
	}
	fakeHosts := map[string]string{
		"12.12.12.12": "noproxy.example.net",
		"10.1.2.3":    "www.example.net",
		"13.12.12.12": "www.example.com",
	}
	findHostName = func(ip string) string {
		return fakeHosts[ip]
	}
	results := map[string]bool{
		"12.12.12.12": false, // in hosts, *.example.net
		"10.1.2.3":    false, // in 10.0.0.0/8
		"13.12.12.12": false, // no proxy
		"10.2.2.3":    true,  // in 10.0.0.0/8
		"192.1.1.1":   false, // not in 192.168.0.0/16
		"192.168.1.1": true,  // in 192.168.0.0/16
	}
	for k, v := range results {
		ip := net.ParseIP(k)
		assert.Equalf(t, v, all(&ip), "ip director for %v?", k)
	}
}

func TestProxyConfig_ResolveHttpProxy(t *testing.T) {
	config := NewProxyConfig(strings.NewReader(data))
	fakeHosts := map[string]string{
		"12.12.12.12": "www.example.org",
		"10.1.2.3":    "www.example.net",
		"13.12.12.12": "www.example.com",
		"12.12.12.13": "www.example1.org",
		"12.12.12.14": "www.example1.net",
	}
	findHostName = func(ip string) string {
		return fakeHosts[ip]
	}
	var defaultProxy, _ = ParseProxy("proxy.example.com:8080")
	results := map[string]*Proxy{
		"172.168.1.1": proxy1,
		"13.12.12.12": proxy1,
		"12.12.12.12": proxy1,
		"12.12.12.13": defaultProxy,
		"12.12.12.14": proxy2,
		"10.1.2.3":    proxy1,
		"1.1.1.1":     defaultProxy,
	}
	for k, v := range results {
		assert.Equalf(t, v, config.ResolveProxy(k, 80, []*Proxy{defaultProxy})[0], "proxy for ip %v?", k)
	}
}

func TestProxyConfig_ResolveSocks5Proxy(t *testing.T) {
	config := NewProxyConfig(strings.NewReader(data))
	fakeHosts := map[string]string{
		"12.12.12.12": "www.example2.io",
		"10.1.2.3":    "www.example.net",
		"13.12.12.12": "www.example.com",
		"12.12.12.13": "www.example1.org",
		"12.12.12.14": "www.example1.net",
	}
	findHostName = func(ip string) string {
		return fakeHosts[ip]
	}
	var defaultProxy, _ = ParseProxy("proxy.example.com:8080")
	results := map[string]*Proxy{
		"172.168.1.1": proxy1,
		"13.12.12.12": proxy1,
		"12.12.12.12": proxy3,
		"12.12.12.13": defaultProxy,
		"12.12.12.14": proxy2,
		"10.1.2.3":    proxy1,
		"1.1.1.1":     defaultProxy,
	}
	for k, v := range results {
		assert.Equalf(t, v, config.ResolveProxy(k, 80, []*Proxy{defaultProxy})[0], "proxy for ip %v?", k)
	}
}
