package main

import (
	"os"
	"os/signal"
	"runtime/pprof"
	"time"

	"github.com/gookit/config/v2"
)

var gMemProfile = config.Default().Bool("writeMemProfile", false)
var gCpuProfile = config.Default().Bool("writeCpuProfile", false)

const memProfilingFile = "proxy-them-all.profiling.mem"
const cpuProfilingFile = "proxy-them-all.profiling.cpu"

func setupProfiling() {
	// Make sure we have enough time to write profile's to disk, even if user presses Ctrl-C
	if !gMemProfile && !gCpuProfile {
		return
	}

	var profilef *os.File
	var err error
	if gMemProfile {
		profilef, err = os.Create(memProfilingFile)
		if err != nil {
			panic(err)
		}
	}

	if gCpuProfile {
		f, err := os.Create(cpuProfilingFile)
		if err != nil {
			panic(err)
		}
		pprof.StartCPUProfile(f)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			if gCpuProfile {
				pprof.StopCPUProfile()
			}
			if gMemProfile {
				pprof.WriteHeapProfile(profilef)
				profilef.Close()
			}
			time.Sleep(5000 * time.Millisecond)
			os.Exit(0)
		}
	}()
}
