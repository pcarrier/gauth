package main

import (
	"bytes"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"path"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/pcarrier/gauth/gauth"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	useCSV = flag.Bool("csv", false, "Output CSV for easy machine processing")
)

func main() {
	flag.Parse()

	cfgPath := os.Getenv("GAUTH_CONFIG")
	if cfgPath == "" {
		usr, err := user.Current()
		if err != nil {
			log.Fatal(err)
		}
		cfgPath = path.Join(usr.HomeDir, ".config/gauth.csv")
	}

	cfgContent, err := gauth.LoadConfigFile(cfgPath, getPassword)
	if err != nil {
		log.Fatalf("Loading config: %v", err)
	}

	cfgReader := csv.NewReader(bytes.NewReader(cfgContent))
	// Unix-style tabular
	cfgReader.Comma = ':'

	cfg, err := cfgReader.ReadAll()
	if err != nil {
		log.Fatalf("Decoding CSV: %v", err)
	}

	currentTS, progress := gauth.IndexNow()

	if *useCSV {
		cw := csv.NewWriter(os.Stdout)
		for _, record := range cfg {
			name, secret := record[0], record[1]
			_, curr, next, err := gauth.Codes(secret, currentTS)
			if err != nil {
				log.Fatalf("Generating codes: %v", err)
			}
			if err := cw.Write([]string{name, curr, next, strconv.Itoa(30 - progress)}); err != nil {
				log.Fatalf("Printing CSV: %v", err)
			}
		}
		cw.Flush()
	} else {
		tw := tabwriter.NewWriter(os.Stdout, 0, 8, 1, ' ', 0)
		if _, err := fmt.Fprintln(tw, "\tprev\tcurr\tnext"); err != nil {
			log.Fatalf("Printing header: %v", err)
		}
		for _, record := range cfg {
			name, secret := record[0], record[1]
			prev, curr, next, err := gauth.Codes(secret, currentTS)
			if err != nil {
				log.Fatalf("Generating codes: %v", err)
			}
			if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", name, prev, curr, next); err != nil {
				log.Fatalf("Printing %v: %v", name, err)
			}
		}
		if err := tw.Flush(); err != nil {
			log.Fatalf("Flushing: %v", err)
		}
		fmt.Printf("[%-29s]\n", strings.Repeat("=", progress))
	}
}

func getPassword() ([]byte, error) {
	if _, err := fmt.Printf("Encryption password: "); err != nil {
		log.Fatalf("Printing encryption password prompt")
	}
	defer fmt.Println()
	return terminal.ReadPassword(syscall.Stdin)
}
