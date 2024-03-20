package main

import (
	"github.com/consensys/gnark-ignition-verifier/ignition"
	"log"
	"os"
)

const TotalG1Points = 100800000

func main() {

	config := ignition.Config{
		BaseURL:  "https://aztec-ignition.s3.amazonaws.com/",
		Ceremony: "MAIN+IGNITION/sealed", // "MAIN IGNITION"
		CacheDir: "../../transcript",
		SrsDir:   "../../srs",
	}
	if config.CacheDir != "" {
		os.MkdirAll(config.CacheDir, os.ModePerm)
	}

	if config.SrsDir != "" {
		os.MkdirAll(config.SrsDir, os.ModePerm)
	}

	// 1. fetch sealed transcript
	srs := ignition.NewContribution(TotalG1Points)
	err := srs.GetSealed(config)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	err = srs.SanityCheck()
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	// 2. split to srs
	for i := 16; i < 27; i++ {
		err = srs.Split(config, i)
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}
	}

}
