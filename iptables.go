package main

import (
	"fmt"
	"math/rand"
	"strings"
	"strconv"

	"net"

	"github.com/coreos/go-iptables/iptables"
	"github.com/gookit/config/v2"
	log "github.com/sirupsen/logrus"
)

type ipTableHandler struct {
	tables             *iptables.IPTables
	mark               int
	listenEndpointPort int
	dnsPort            int
	proxyPorts     string
	outputChain    string
	preOutingChain string
}

func LoadIPTables() *ipTableHandler {
	var listenEndpointPort int

	var lnaddr *net.TCPAddr
	var err error
	if lnaddr, err = net.ResolveTCPAddr("tcp", config.Default().String("listenEndpoint", "127.0.0.1:3129")); err != nil {
		panic(err)
	} else {
		listenEndpointPort = lnaddr.Port
	}
	ipTableHandler, err := InstallIPTables(config.Default().String("ignorePorts", "80,443"), listenEndpointPort, ipTableMark)
	if err != nil {
		ipTableHandler.Uninstall()
		panic(err)
	}
	log.Infof("Installed iptables to redirect streams to port %v (with ignored ports %v)", listenEndpointPort, config.Default().String("ignorePorts", "80,443"))

	return ipTableHandler
}

func InstallIPTables(proxyPorts string, listenEndpointPort int, mark int) (handler *ipTableHandler, err error) {
	tables, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, err
	}

	//_RANDOM=${RANDOM}
	random := rand.Intn(1 << 16)
	var dnsPort int
	if dnsPort, err = strconv.Atoi(strings.Split(config.Default().String("DnsProxyEndPoint", "127.0.0.1:53"), ":")[1]); err != nil {
		return nil, err
	}

	//IPTABELE_OUTPUT_CHAIN=PROXY_OUTPUT_${_RANDOM}
	outputChain := fmt.Sprintf("PROXY_OUTPUT_%d", random)

	//IPTABELE_PREROUTING_CHAIN=PROXY_PREROUTING_${_RANDOM}
	preOutingChain := fmt.Sprintf("PROXY_PREROUTING_%d", random)

	handler = &ipTableHandler{
		tables:             tables,
		mark:               mark,
		listenEndpointPort: listenEndpointPort,
		dnsPort:            dnsPort,
		proxyPorts:     proxyPorts,
		outputChain:    outputChain,
		preOutingChain: preOutingChain,
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
	dnsPort := h.dnsPort

	//   iptables -t filter -D OUTPUT -p tcp -m mark --mark ${IPTABLE_MARK} --dport ${LISTEN_PORT} -j REJECT
	if err := tables.Delete("filter", "OUTPUT",
		args("-p tcp -m mark --mark %d --dport %d -j REJECT", mark, listenEndpointPort)...); err != nil {
		return err
	}

	//  iptables -t nat -D OUTPUT -p tcp -m mark ! --mark ${IPTABLE_MARK} -m multiport --dports ${PROXY_PORTS} -j ${IPTABELE_OUTPUT_CHAIN}
	if err := tables.Delete("nat", "OUTPUT",
		args("-p tcp -m mark ! --mark %d -m multiport --dports %s -j %s", mark, proxyPorts, outputChain)...); err != nil {
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
	if err := tables.Delete("nat", "PREROUTING",
		args("-p tcp -m mark ! --mark %d -m multiport --dports %s -j %s", mark, proxyPorts, preOutingChain)...); err != nil {
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

	//  if [ "${DNS_PORT}" -gt 0 ]; then
	if dnsPort > 0 {
		// iptables -t nat -D OUTPUT -p udp -m mark ! --mark ${IPTABLE_MARK} -m multiport --dports ${DNS_PORT} -j REDIRECT --to-port ${LISTEN_PORT}
		if err := tables.Delete("nat", "OUTPUT",
			args("-p udp -m mark ! --mark %d -m multiport --dports %d -j REDIRECT --to-port %d", mark, dnsPort, listenEndpointPort)...); err != nil {
			return err
		}

		// iptables -t nat -D PREROUTING -p udp -m multiport --dports ${DNS_PORT} -j REDIRECT --to-port ${LISTEN_PORT}
		if err := tables.Delete("nat", "PREROUTING",
			args("-p udp -m multiport --dports %d -j REDIRECT --to-port %d", dnsPort, listenEndpointPort)...); err != nil {
			return err
		}
	}

	return nil
}

