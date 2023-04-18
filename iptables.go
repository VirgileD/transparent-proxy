package main

import (
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strings"

	"net"

	"github.com/coreos/go-iptables/iptables"
	"github.com/emirpasic/gods/sets/hashset"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func autoDiscoverDirects() ([]string, error) {
	var noProxyList []string = cfg.NoProxyList
	if routes, err := netlink.RouteList(nil, netlink.FAMILY_V4); err != nil {
		return nil, err
	} else {
		set := hashset.New()
		// default configured noProxy
		sort.Strings(noProxyList)
		log.Infof("Adding auto-discovered direct routes to configuration %v", noProxyList)
		s := make([]interface{}, len(noProxyList))
		for i, v := range noProxyList {
			s[i] = v
		}
		set.Add(s...)
		// add autodiscovered
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
		log.Infof("After auto-dicovering to %v", items)
		return items, nil
	}
}

type ipTableHandler struct {
	tables             *iptables.IPTables
	mark               int
	listenEndpointPort int
	proxyPorts         string
	outputChain        string
	preOutingChain     string
}

func LoadIPTables() *ipTableHandler {
	var listenEndpoint = cfg.ListenEndpoint
	var proxyPorts string = cfg.ProxyPorts

	var listenEndpointPort int
	var lnaddr *net.TCPAddr
	var err error
	if lnaddr, err = net.ResolveTCPAddr("tcp", listenEndpoint); err != nil {
		panic(err)
	} else {
		listenEndpointPort = lnaddr.Port
	}
	ipTableHandler, err := InstallIPTables(proxyPorts, listenEndpointPort, cfg.IpTableMark)
	if err != nil {
		ipTableHandler.Uninstall()
		panic(err)
	}
	log.Infof("Installed iptables to redirect ports %v to port %v", proxyPorts, listenEndpointPort)

	return ipTableHandler
}

func InstallIPTables(proxyPorts string, listenEndpointPort int, mark int) (handler *ipTableHandler, err error) {
	var autoDiscoveredDirectDestinations []string
	if autoDiscoveredDirectDestinations, err = autoDiscoverDirects(); err != nil {
		log.Fatalf("Error while auto discovering direct rules: %v", err)
		os.Exit(1)
	}
	var noProxyString string = strings.Join(autoDiscoveredDirectDestinations, ",")

	tables, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, err
	}

	//_RANDOM=${RANDOM}
	random := rand.Intn(1 << 16)
	var dnsPort int = 53

	//IPTABELE_OUTPUT_CHAIN=PROXY_OUTPUT_${_RANDOM}
	outputChain := fmt.Sprintf("PROXY_OUTPUT_%d", random)

	//IPTABELE_PREROUTING_CHAIN=PROXY_PREROUTING_${_RANDOM}
	preOutingChain := fmt.Sprintf("PROXY_PREROUTING_%d", random)

	handler = &ipTableHandler{
		tables:             tables,
		mark:               mark,
		listenEndpointPort: listenEndpointPort,
		proxyPorts:         proxyPorts,
		outputChain:        outputChain,
		preOutingChain:     preOutingChain,
	}

	//  iptables -t filter -I OUTPUT 1 -p tcp -m mark --mark ${IPTABLE_MARK} --dport ${LISTEN_PORT} -j REJECT
	if err = tables.Insert("filter", "OUTPUT", 1, args("-p tcp -m mark --mark %d --dport %d -j REJECT", mark, listenEndpointPort)...); err != nil {
		return handler, err
	}
	handler.tables = tables

	//  iptables -t nat -N ${IPTABELE_OUTPUT_CHAIN}
	if err = tables.NewChain("nat", outputChain); err != nil {
		return handler, err
	}
	handler.tables = tables

	//  iptables -t nat -A ${IPTABELE_OUTPUT_CHAIN} -p tcp -j RETURN -d ${NO_PROXY_LIST}
	if err = tables.Append("nat", outputChain, args("-p tcp -j RETURN -d %s", noProxyString)...); err != nil {
		return handler, err
	}
	handler.tables = tables

	//  iptables -t nat -A ${IPTABELE_OUTPUT_CHAIN} -p tcp -j REDIRECT --to-port ${LISTEN_PORT}
	if err = tables.Append("nat", outputChain, args("-p tcp -j REDIRECT --to-port %d", listenEndpointPort)...); err != nil {
		return handler, err
	}
	handler.tables = tables

	//  iptables -t nat -A OUTPUT -p tcp -m mark ! --mark ${IPTABLE_MARK} -m multiport --dports ${PROXY_PORTS} -j ${IPTABELE_OUTPUT_CHAIN}
	if err = tables.Append("nat", "OUTPUT", args("-p tcp -m mark ! --mark %d -m multiport --dports %s -j %s", mark, proxyPorts, outputChain)...); err != nil {
		return handler, err
	}
	handler.tables = tables

	//  iptables -t nat -N ${IPTABELE_PREROUTING_CHAIN}
	if err = tables.NewChain("nat", preOutingChain); err != nil {
		return handler, err
	}
	handler.tables = tables

	//  iptables -t nat -A ${IPTABELE_PREROUTING_CHAIN} -p tcp -j RETURN -d ${NO_PROXY_LIST}
	if err = tables.Append("nat", preOutingChain, args("-p tcp -j RETURN -d %s", noProxyString)...); err != nil {
		return handler, err
	}
	handler.tables = tables

	//  iptables -t nat -A ${IPTABELE_PREROUTING_CHAIN} -p tcp -j MARK --set-mark ${IPTABLE_MARK}
	if err = tables.Append("nat", preOutingChain, args("-p tcp -j MARK --set-mark %d", mark)...); err != nil {
		return handler, err
	}
	handler.tables = tables

	//  iptables -t nat -A ${IPTABELE_PREROUTING_CHAIN} -p tcp -j REDIRECT --to-port ${LISTEN_PORT}
	if err = tables.Append("nat", preOutingChain, args("-p tcp -j REDIRECT --to-port %d", listenEndpointPort)...); err != nil {
		return handler, err
	}
	handler.tables = tables

	//  iptables -t nat -A PREROUTING -p tcp -m mark ! --mark ${IPTABLE_MARK} -m multiport --dports ${PROXY_PORTS} -j ${IPTABELE_PREROUTING_CHAIN}
	if err = tables.Append("nat", "PREROUTING", args("-p tcp -m mark ! --mark %d -m multiport --dports %s -j %s", mark, proxyPorts, preOutingChain)...); err != nil {
		return handler, err
	}

	//  iptables -t filter -I INPUT 1 -p tcp -m mark --mark ${IPTABLE_MARK} --dport ${LISTEN_PORT} -m conntrack --ctstate NEW -j ACCEPT
	if err = tables.Insert("filter", "INPUT", 1, args("-p tcp -m mark --mark %d --dport %d -m conntrack --ctstate NEW -j ACCEPT", mark, listenEndpointPort)...); err != nil {
		return handler, err
	}
	handler.tables = tables

	// iptables -t nat -A OUTPUT -p udp -m mark ! --mark ${IPTABLE_MARK} -m multiport --dports ${DNS_PORT} -j REDIRECT --to-port ${LISTEN_PORT}
	if err = tables.Append("nat", "OUTPUT",
		args("-p udp -m mark ! --mark %d -m multiport --dports %d -j REDIRECT --to-port %d", mark, dnsPort, listenEndpointPort)...); err != nil {
		return handler, err
	}
	handler.tables = tables
	// iptables -t nat -A PREROUTING -p udp -m multiport --dports ${DNS_PORT} -j REDIRECT --to-port ${LISTEN_PORT}
	if err = tables.Append("nat", "PREROUTING",
		args("-p udp -m multiport --dports %d -j REDIRECT --to-port %d", dnsPort, listenEndpointPort)...); err != nil {
		return handler, err
	}
	handler.tables = tables

	return handler, nil
}

func args(format string, a ...interface{}) []string {
	return strings.Split(fmt.Sprintf(format, a...), " ")
}

func (h *ipTableHandler) Uninstall() error {
	tables := h.tables
	outputChain := h.outputChain
	preOutingChain := h.preOutingChain
	mark := h.mark
	listenEndpointPort := h.listenEndpointPort
	proxyPorts := h.proxyPorts

	//   iptables -t filter -D OUTPUT -p tcp -m mark --mark ${IPTABLE_MARK} --dport ${LISTEN_PORT} -j REJECT
	if err := tables.Delete("filter", "OUTPUT", args("-p tcp -m mark --mark %d --dport %d -j REJECT", mark, listenEndpointPort)...); err != nil {
		return err
	}

	//  iptables -t nat -D OUTPUT -p tcp -m mark ! --mark ${IPTABLE_MARK} -m multiport --dports ${PROXY_PORTS} -j ${IPTABELE_OUTPUT_CHAIN}
	if err := tables.Delete("nat", "OUTPUT", args("-p tcp -m mark ! --mark %d -m multiport --dports %s -j %s", mark, proxyPorts, outputChain)...); err != nil {
		return err
	}

	//  iptables -t nat -F ${IPTABELE_OUTPUT_CHAIN}
	if err := tables.ClearChain("nat", outputChain); err != nil {
		return err
	}

	//  iptables -t nat -X ${IPTABELE_OUTPUT_CHAIN}
	if err := tables.DeleteChain("nat", outputChain); err != nil {
		return err
	}

	//  iptables -t nat -D PREROUTING -p tcp -m mark ! --mark ${IPTABLE_MARK} -m multiport --dports ${PROXY_PORTS} -j ${IPTABELE_PREROUTING_CHAIN}
	if err := tables.Delete("nat", "PREROUTING", args("-p tcp -m mark ! --mark %d -m multiport --dports %s -j %s", mark, proxyPorts, preOutingChain)...); err != nil {
		return err
	}

	//  iptables -t nat -F ${IPTABELE_PREROUTING_CHAIN}
	if err := tables.ClearChain("nat", preOutingChain); err != nil {
		return err
	}

	//  iptables -t nat -X ${IPTABELE_PREROUTING_CHAIN}
	if err := tables.DeleteChain("nat", preOutingChain); err != nil {
		return err
	}

	//  iptables -t filter -D INPUT -p tcp -m mark --mark ${IPTABLE_MARK} --dport ${LISTEN_PORT} -m conntrack --ctstate NEW -j ACCEPT
	if err := tables.Delete("filter", "INPUT",
		args("-p tcp -m mark --mark %d --dport %d -m conntrack --ctstate NEW -j ACCEPT", mark, listenEndpointPort)...); err != nil {
		return err
	}

	// iptables -t nat -D OUTPUT -p udp -m mark ! --mark ${IPTABLE_MARK} -m multiport --dports ${DNS_PORT} -j REDIRECT --to-port ${LISTEN_PORT}
	if err := tables.Delete("nat", "OUTPUT", args("-p udp -m mark ! --mark %d -m multiport --dports %d -j REDIRECT --to-port %d", mark, 53, listenEndpointPort)...); err != nil {
		return err
	}

	// iptables -t nat -D PREROUTING -p udp -m multiport --dports ${DNS_PORT} -j REDIRECT --to-port ${LISTEN_PORT}
	if err := tables.Delete("nat", "PREROUTING", args("-p udp -m multiport --dports %d -j REDIRECT --to-port %d", 53, listenEndpointPort)...); err != nil {
		return err
	}

	return nil
}
