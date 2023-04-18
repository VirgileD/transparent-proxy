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
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
)

func versionString() string {
	goVersion := runtime.Version()
	return fmt.Sprintf("prox-them-all %s (build %v by %v@%v) - %s", VERSION, BUILDTIMESTAMP, BUILDUSER, BUILDHOST, goVersion)
}

const SO_ORIGINAL_DST = 80
const DEFAULTLOG = "/var/log/proxy-them-all.log"
const STATSFILE = "/var/log/proxy-them-all.stats"

var loglevels = map[string]log.Level{"panic": log.PanicLevel, "fatal": log.FatalLevel, "error": log.ErrorLevel,
	"warning": log.WarnLevel, "info": log.InfoLevel, "debug": log.DebugLevel, "trace": log.TraceLevel}

func setupLogging() {
	log.SetOutput(os.Stdout)
	log.SetLevel(loglevels[cfg.LogLevel])
}

var configFile string
var displayVers bool
var resetIPTables bool

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stdout, "%s\n\n", versionString())
		fmt.Fprintf(os.Stdout, "usage: %s [-c configFile]\n", os.Args[0])
		fmt.Fprintf(os.Stdout, "       Proxies any tcp port transparently using Linux netfilter\n\n")
		fmt.Fprintf(os.Stdout, "Optional\n")
		fmt.Fprintf(os.Stdout, "  -c configFile absolute path to the config file, default to /etc/proxy-them-all/config.json \n")
		fmt.Fprintf(os.Stdout, "  -R reset iptables \n")
		fmt.Fprintf(os.Stdout, "  -v Display version \n")
	}
	flag.StringVar(&configFile, "c", "", "configuration file, default to /etc/proxy-them-all/config.json.\n")
	flag.BoolVar(&resetIPTables, "R", false, "Reset IPTables.\n")
	flag.BoolVar(&displayVers, "v", false, "Use to display version information.\n")
}

var stopped = false

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU() / 2)

	flag.Parse()
	if displayVers {
		fmt.Fprintf(os.Stdout, "%s\n\n", versionString())
		os.Exit(0)
	}

	if configFile == "" {
		configFile = "/etc/proxy-them-all/config.json"
	}
	LoadConfig(configFile)

	setupLogging()
	setupProfiling()
	setupStats()
	setupStackDump()
	dnsProxyServer := LoadDnsServer()
	defer dnsProxyServer.Close()

	LoadReverseLookupCache()

	listener := StartListening()
	listenerStop := new(sync.Once)
	defer listenerStop.Do(func() {
		_ = listener.Close()
	})

	ipTableUninstaller := new(sync.Once)
	ipTableHandler := LoadIPTables()
	defer ipTableUninstaller.Do(func() {
		err := ipTableHandler.Uninstall()
		log.Infof("Uninstalled iptables for ports %v", ipTableHandler.proxyPorts)
		if err != nil {
			log.Warningf("Got error during uninstall iptables: %v", err)
		}
	})

	// stop handler
	go func() {
		sigs := make(chan os.Signal, 6)
		signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
		signal.Notify(sigs, os.Interrupt, syscall.SIGINT)
		signal.Notify(sigs, os.Interrupt, syscall.SIGABRT)
		signal.Notify(sigs, os.Interrupt, syscall.SIGKILL)
		signal.Notify(sigs, os.Interrupt, syscall.SIGQUIT)
		signal.Notify(sigs, os.Interrupt, syscall.SIGSEGV)
		<-sigs
		stopped = true
		listenerStop.Do(func() {
			_ = listener.Close()
		})
		ipTableUninstaller.Do(func() {
			err := ipTableHandler.Uninstall()
			log.Infof("Uninstalled iptables for ports %v", ipTableHandler.proxyPorts)
			if err != nil {
				log.Warningf("Got error during uninstall iptables: %v", err)
			}
		})
	}()

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			if stopped {
				log.Infof("Stopping Listening")
				break
			}
			log.Infof("Error accepting connection: %v", err)
			incrAcceptErrors()
			continue
		}
		incrAcceptSuccesses()
		log.Debugf("main(): Get new connection:%+v", conn.RemoteAddr())
		go handleConnection(conn)
	}

}

func StartListening() *net.TCPListener {
	lnaddr, err := net.ResolveTCPAddr("tcp", cfg.ListenEndpoint)
	if err != nil {
		panic(err)
	}

	listener, err := net.ListenTCP("tcp", lnaddr)
	if err != nil {
		panic(err)
	}

	log.Infof("Listening for connections on %v", listener.Addr())
	return listener
}
