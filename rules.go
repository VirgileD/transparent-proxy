package main

import (
	"os"

	orderedmap "github.com/wk8/go-ordered-map/v2"

	"github.com/gookit/config/v2"
	log "github.com/sirupsen/logrus"
)

type BindingRule struct {
	name          string    `mapstructure:"name"`
	destinations  []string  `mapstructure:"destinations"`
	stringProxies *[]string `mapstructure:"proxies"`
}

type Rule struct {
	destinations []string
	proxies      []*Proxy
}

var rules = orderedmap.New[string, Rule]()

func LoadRules() {
	var tmpRules []BindingRule = make([]BindingRule, 20)
	var err error

	err = config.BindStruct("rules", &tmpRules)
	if err != nil {
		log.Fatalf("Error while reading rules: %v", err)
		os.Exit(1)
	}

	err = config.BindStruct("rules", &tmpRules)
	if err != nil {
		log.Fatalf("Error while reading rules: %v", err)
		os.Exit(1)
	}

	for _, element := range tmpRules {
		var proxies []*Proxy
		proxies, err = ParseProxyList(element.stringProxies)
		if err != nil {
			log.Fatalf("Error while reading rule %s's proxies: %v", element.name, err)
			os.Exit(1)
		}
		rules.Set(element.name, Rule{destinations: element.destinations, proxies: proxies})
	}
}
