package main

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/miekg/dns"
	logger "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

const remoteDns = "8.8.8.8:53"

func init() {
	if iptablesIntegration {
		logger.Info("use iptables integration on root mode for dns proxy testing")
	}
}

func TestRemoteDns(t *testing.T) {
	assert := assert.New(t)
	var testDomain = [...]string{"www.example.com.", "github.com."}
	for _, domain := range testDomain {
		m := new(dns.Msg)
		m.SetQuestion(domain, dns.TypeA)
		r, err := dns.Exchange(m, remoteDns)
		if err != nil {
			t.Fatalf("failed query dns %q: %v", remoteDns, err)
		}
		if r != nil && r.Rcode != dns.RcodeSuccess {
			t.Fatalf("failed query %q: %v", m.Question, r)
		}
		assert.True(len(r.Answer) >= 1)
	}
}

func randomPort() int {
	return rand.Intn(65535-1024) + 1024
}

func TestDnsProxy_ListenAndServe(t *testing.T) {
	assert := assert.New(t)
	localDns := fmt.Sprintf("127.0.0.1:%v", randomPort())
	// setup proxy
	proxy := NewDnsProxy(localDns, remoteDns)
	defer proxy.Close()
	if err := proxy.ListenAndServe(false); err != nil {
		t.Fatalf("failed open dns proxy on %q: %v", localDns, err)
	}
	m := new(dns.Msg)
	m.SetQuestion("www.example.com.", dns.TypeA)
	r, err := dns.Exchange(m, localDns)
	if err != nil {
		t.Fatalf("failed query dns %q: %v", remoteDns, err)
	}
	if r != nil && r.Rcode != dns.RcodeSuccess {
		t.Fatalf("failed query %q: %v", m.Question, r)
	}
	assert.True(len(r.Answer) >= 1)
}

func TestDnsProxy_ListHostNames(t *testing.T) {
	assert := assert.New(t)
	localDns := fmt.Sprintf(":%v", randomPort())
	// setup proxy
	proxy := NewDnsProxy(localDns, remoteDns)
	defer proxy.Close()
	if err := proxy.ListenAndServe(false); err != nil {
		t.Fatalf("failed open dns proxy on %q: %v", localDns, err)
	}
	var testDomain = [...]string{"github.com.", "www.example.com."}
	for _, domain := range testDomain {
		m := new(dns.Msg)
		m.SetQuestion(domain, dns.TypeA)
		r, err := dns.Exchange(m, localDns)
		if err != nil {
			t.Fatalf("failed query dns %q: %v", remoteDns, err)
		}
		if r != nil && r.Rcode != dns.RcodeSuccess {
			t.Fatalf("failed query %q: %v", m.Question, r)
		}
		assert.True(len(r.Answer) >= 1)
	}
	names := ListHostNames()
	assert.Equal(len(testDomain), len(names))
	for _, domain := range testDomain {
		ip, ok := names[domain]
		logger.Debugf("Hostname %v ip is %v", domain, ip)
		assert.Truef(ok, "hostname %v is not queried", domain)
	}
}
