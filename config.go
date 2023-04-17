package main

import (
	"fmt"

	"github.com/gookit/config/v2"
	"github.com/gookit/config/v2/json"
)

func LoadConfig(f string) {
	config.AddDriver(json.Driver)

	err := config.LoadFiles(f)
	if err != nil {
		panic(err)
	}

	fmt.Printf("config data: \n %#v\n", config.Data())
}
