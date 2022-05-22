package main

import (
	"flag"
	"fmt"
	"os"

	"git.mfdlabs.local/petko/mfdlabs-ssl-go/pkg"
	"git.mfdlabs.local/petko/mfdlabs-ssl-go/pkg/certificates"
	"git.mfdlabs.local/petko/mfdlabs-ssl-go/pkg/configuration"
	"git.mfdlabs.local/petko/mfdlabs-ssl-go/pkg/ssl"
)

var configurationFilePath = flag.String("configurationFilePath", "", "The path to the configuration file. Can be absolute or relative to the current working directory. Can be a json or yaml file.")

func main() {
	flag.Usage = func() {
		fmt.Println("ssl-go [options]")
		flag.PrintDefaults()
	}

	flag.Parse()

	// Determine if the configuration file path is empty
	if *configurationFilePath == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Error out if we aren't running on unix
	if os.PathSeparator != '/' {
		panic("This program is only supported on unix systems")
	}

	// If the ./bin directory doesn't exist, create it
	if _, err := os.Stat("./bin"); os.IsNotExist(err) {
		err = os.Mkdir("./bin", 0755)

		if err != nil {
			panic(err)
		}
	}

	// Determine if generation scripts are available
	err := ssl.DetermineIfScriptsAvailable()

	if err != nil {
		panic(err)
	}

	// Load the configuration file
	conf, err := pkg.LoadConfiguration(*configurationFilePath)

	if err != nil {
		panic(err)
	}

	loadedRootCerts := make(map[string]*configuration.RootCertificateAuthority)
	loadedIntermediateCerts := make(map[string]*configuration.IntermediateCertificateAuthority)

	certificates.Run(*configurationFilePath, conf, loadedRootCerts, loadedIntermediateCerts)
}
