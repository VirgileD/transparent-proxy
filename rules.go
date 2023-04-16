package main

import (
	"fmt"
	"log"
	"os"
	"sort"

	orderedmap "github.com/wk8/go-ordered-map/v2"

	"github.com/emirpasic/gods/sets/hashset"
	"github.com/gookit/config/v2"
	"github.com/vishvananda/netlink"
)

func autoDiscoverDirects() ([]string, error) {
	if routes, err := netlink.RouteList(nil, netlink.FAMILY_V4); err != nil {
		return nil, err
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
		return items, nil
	}
}

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
	var tmpRules []BindingRule
	var err error

	err = config.BindStruct("rules", &tmpRules)
	if err != nil {
		log.Fatalf("Error while reading rules: %v", err)
		os.Exit(1)
	}

	var autoDiscoveredDirectDestinations []string
	if autoDiscoveredDirectDestinations, err = autoDiscoverDirects(); err != nil {
		log.Fatalf("Error while auto discovering direct rules: %v", err)
		os.Exit(1)
	}

	rules.Set("AutoDiscovered", Rule{destinations: autoDiscoveredDirectDestinations, proxies: nil})

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
