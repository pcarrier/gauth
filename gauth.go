package main

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"os/user"
	"path"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/pcarrier/gauth/gauth"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	cfgPath := os.Getenv("GAUTH_CONFIG")
	if cfgPath == "" {
		user, err := user.Current()
		if err != nil {
			log.Fatal(err)
		}
		cfgPath = path.Join(user.HomeDir, ".config/gauth.csv")
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

	tw := tabwriter.NewWriter(os.Stdout, 0, 8, 1, ' ', 0)
	fmt.Fprintln(tw, "\tprev\tcurr\tnext")
	for _, record := range cfg {
		name, secret := record[0], record[1]
		prev, curr, next, err := gauth.Codes(secret, currentTS)
		if err != nil {
			log.Fatalf("Generating codes: %v", err)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", name, prev, curr, next)
	}
	tw.Flush()
	fmt.Printf("[%-29s]\n", strings.Repeat("=", progress))
}

func getPassword() ([]byte, error) {
	fmt.Printf("Encryption password: ")
	defer fmt.Println()
	return terminal.ReadPassword(int(syscall.Stdin))
}
