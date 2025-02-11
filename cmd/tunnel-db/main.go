package main

import (
	"os"

	"github.com/khulnasoft-lab/tunnel-db/pkg"
	"github.com/khulnasoft-lab/tunnel-db/pkg/log"
)

var (
	version = "0.0.1"
)

func main() {
	ac := pkg.AppConfig{}
	app := ac.NewApp(version)
	err := app.Run(os.Args)
	if err != nil {
		log.Errorf("%+v", err)
		os.Exit(1)
	}
}
