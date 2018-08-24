package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"golang.org/x/net/proxy"
	"net/url"
	"encoding/base64"
)

type ProxyType string

var (
	HttpProxyType   ProxyType = "http"
	Socks5ProxyType ProxyType = "socks5"
)

func (typ *ProxyType) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var typeString string
	err := unmarshal(&typeString)
	if err != nil {
		return err
	}

	*typ, err = ParseProxyType(typeString)

	return err
}

func ParseProxyType(typeString string) (typ ProxyType, err error) {
	newType := ProxyType(typeString)

	switch newType {
	case HttpProxyType, Socks5ProxyType:
		typ = newType
	default:
		err = fmt.Errorf("invalid proxy type '%s'", newType)
	}
	return
}

type Proxy struct {
	Host string
	Port uint16
	Type ProxyType
	Auth *proxy.Auth
}

func NewProxy(host string, port uint16, typ ProxyType) *Proxy {
	return &Proxy{
		Host: host,
		Port: port,
		Type: typ,
	}
}

func (p *Proxy) HostPort() string {
	return fmt.Sprintf("%s:%d", p.Host, p.Port)
}

func (p *Proxy) ToURL() *url.URL {
	var u = new(url.URL)
	u.Host = p.HostPort()
	u.Scheme = string(p.Type)
	if p.Auth != nil {
		if p.Auth.Password == "" {
			u.User = url.User(p.Auth.User)
		} else {
			u.User = url.UserPassword(p.Auth.User, p.Auth.Password)
		}
	}
	return u
}

func (p *Proxy) String() string {
	return p.ToURL().String()
}

func (p *Proxy) UserInfoBase64() string {
	if p.Auth == nil {
		return ""
	} else {
		return base64.StdEncoding.EncodeToString([]byte(p.Auth.User + ":" + p.Auth.Password))
	}
}

func ParseProxy(proxySpec string) (*Proxy, error) {
	var proxyType = HttpProxyType // default proxy is http
	var auth *proxy.Auth = nil
	if strings.Contains(proxySpec, "://") {
		var strProxyType string
		strProxyType, proxySpec = split(proxySpec, "://")
		var err error
		proxyType, err = ParseProxyType(strProxyType)
		if err != nil {
			return nil, err
		}
	}
	if strings.Contains(proxySpec, "@") {
		var userInfo string
		userInfo, proxySpec = split(proxySpec, "@")
		if strings.Contains(userInfo, ":") {
			username, password := split(userInfo, ":")
			auth = &proxy.Auth{User: username, Password: password}
		} else {
			auth = &proxy.Auth{User: userInfo}
		}
	}

	proxyHost, proxyPort, err := net.SplitHostPort(proxySpec)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy host:port format: '%s' (%s)", proxySpec, err)
	}
	proxyPortInt, err := strconv.Atoi(proxyPort)
	if err != nil {
		return nil, fmt.Errorf("could not convert network port from string \"%s\" to integer: %v", proxyPort, err)
	}
	var p = NewProxy(proxyHost, uint16(proxyPortInt), proxyType)
	p.Auth = auth
	return p, nil
}

func split(s string, c string) (string, string) {
	i := strings.Index(s, c)
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i+len(c):]
}

func ParseProxyList(proxyList string) ([]*Proxy, error) {
	list := strings.Split(proxyList, ",")
	pList := make([]*Proxy, len(list))
	for i, proxySpec := range list {
		var err error
		pList[i], err = ParseProxy(proxySpec)
		if err != nil {
			return nil, err
		}
	}
	return pList, nil
}
