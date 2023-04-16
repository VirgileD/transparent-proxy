package main

import (
	"os"
	"os/signal"
	"runtime/pprof"
	"time"
)

func setupProfiling() {
	// Make sure we have enough time to write profile's to disk, even if user presses Ctrl-C
	if gMemProfile == "" || gCpuProfile == "" {
		return
	}

	var profilef *os.File
	var err error
	if gMemProfile != "" {
		profilef, err = os.Create(gMemProfile)
		if err != nil {
			panic(err)
		}
	}

	if gCpuProfile != "" {
		f, err := os.Create(gCpuProfile)
		if err != nil {
			panic(err)
		}
		pprof.StartCPUProfile(f)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			if gCpuProfile != "" {
				pprof.StopCPUProfile()
			}
			if gMemProfile != "" {
				pprof.WriteHeapProfile(profilef)
				profilef.Close()
			}
			time.Sleep(5000 * time.Millisecond)
			os.Exit(0)
		}
	}()
}
