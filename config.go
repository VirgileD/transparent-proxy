package main

import (
	"fmt"
	"os"

	"github.com/cristalhq/aconfig"
	orderedmap "github.com/wk8/go-ordered-map/v2"

	log "github.com/sirupsen/logrus"
)

type ProxEmAllConfig struct {
	IpTableMark              int      `default:"5"`
	ListenEndpoint           string   `default:"127.0.0.1:3129"`
	ProxyPorts               string   `default:"80,443"`
	NoProxyList              []string `default:"[\"127.0.0.1/8\",\"192.168.0.1/16\",\"172.16.0.0/12\"]"`
	WriteMemProfile          bool     `default:"false"`
	WriteCpuProfile          bool     `default:"false"`
	RelayingRedirectResponse bool     `default:"true"`
	LogLevel                 string   `default:"info"`
	Rules                    []struct {
		Name         string   `rules:"name"`
		Destinations []string `rules:"destinations"`
		Proxies      []string `rules:"proxies"`
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
		log.Infof("Adding rule %s with proxies: %v for destination %v", element.Name, proxies, element.Destinations)
		rules.Set(element.Name, Rule{destinations: element.Destinations, proxies: proxies})
	}
}
