package main

import (
	"fmt"
	"os"

	"github.com/cristalhq/aconfig"
	orderedmap "github.com/wk8/go-ordered-map/v2"

	log "github.com/sirupsen/logrus"
)

type ProxEmAllConfig struct {
	IpTableMark              int      `json:"ipTableMark" default:"5" usage:"Table mark used in iptables"`
	ListenEndpoint           string   `json:"listenEndpoint" default:"127.0.0.1:3129" usage:"This proxy endpoint"`
	ProxyPorts               string   `json:"proxyPorts" default:"80,443" usage="The ports to redirect to this proxy"`
	NoProxyList              []string `json:"noProxyList" default:"[]" usage="a list of netmask that will never be redirected to this proxy - auto-discovering should do in most cases"`
	WriteMemProfile          bool     `json:"writeMemProfile" default:"false" usage:"write the mem profiling in proxy-them-all.profiling.mem file"`
	WriteCpuProfile          bool     `json:"writeCpuProfile" default:"false" usage:"write the cpu profiling in proxy-them-all.profiling.cpu file"`
	RelayingRedirectResponse bool     `json:"relayingRedirectResponse" default:"true" usage:"when the destination answer with a 3XX, relay the response to the caller so it can update the destination url"`
	LogLevel                 string   `json:"loglevel" default:"info" usage:"set the log level between: panic, fatal, error, warning, info, debug, trace. panic and fatal will terminate the process"`
	Rules                    []struct {
		Name         string   `json:"name" usage:"A human name for this specific proxying rule"`
		Destinations []string `json:"destinations" usage:"If one of the destinations here corresponds to the requested one, use the proxies defined in this rule. It can be an IP, a CIDR or a regex that must match the destination hostname"`
		Proxies      []string `json:"proxies" usage:"a list of socks:// or http:// proxy to use when this rule apply. Apply in order, if one fails the next is used until no proxy remains. In this case try a direct connection."`
	}
}

type Rule struct {
	destinations []string
	proxies      []*Proxy
}

var rules = orderedmap.New[string, Rule]()
var cfg ProxEmAllConfig

func LoadConfig(configFile string) {
	var err error
	fmt.Printf("Loading config file: %v\n", configFile)
	loader := aconfig.LoaderFor(&cfg, aconfig.Config{
		AllowUnknownFields: true,
		SkipEnv:            true,
		SkipFlags:          true,
		Files:              []string{configFile},
	})
	if err = loader.Load(); err != nil {
		log.Panic(err)
	}
	loader.WalkFields(func(f aconfig.Field) bool {
		fmt.Printf("%v: %q %q %q %q\n", f.Name(), f.Tag("env"), f.Tag("flag"), f.Tag("default"), f.Tag("usage"))
		return true
	})
	fmt.Printf("ipTableMark: %v\n", cfg.IpTableMark)
	fmt.Printf("listenEndpoint: %v\n", cfg.ListenEndpoint)
	fmt.Printf("proxyPorts: %v\n", cfg.ProxyPorts)
	fmt.Printf("noProxyList: %v\n", cfg.NoProxyList)
	fmt.Printf("writeCpuProfile: %v\n", cfg.WriteCpuProfile)
	fmt.Printf("writeMemProfile: %v\n", cfg.WriteMemProfile)
	fmt.Printf("relayingRedirectResponse: %v\n", cfg.RelayingRedirectResponse)
	fmt.Printf("loglevel: %v\n", cfg.LogLevel)

	for _, element := range cfg.Rules {
		var proxies []*Proxy
		proxies, err = ParseProxyList(&element.Proxies)
		if err != nil {
			log.Fatalf("Error while reading rule %s's proxies: %v", element.Name, err)
			os.Exit(1)
		}
		log.Infof("Adding rule %s with proxies: %v for destinations %v", element.Name, element.Proxies, element.Destinations)
		rules.Set(element.Name, Rule{destinations: element.Destinations, proxies: proxies})
	}
}
