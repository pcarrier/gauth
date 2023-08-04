package main

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/creachadair/otp/otpauth"
	"github.com/pcarrier/gauth/gauth"
	"golang.org/x/term"
)

func main() {
	accountName := ""
	isBareCode := false

	if len(os.Args) > 1 {
		accountName = os.Args[1]
	}
	if len(os.Args) > 2 {
		if os.Args[2] == "-b" || os.Args[2] == "-bare" {
			isBareCode = true
		}
	}

	urls := getUrls()

	if isBareCode && accountName != "" {
		printBareCode(accountName, urls)
	} else {
		printAllCodes(urls)
	}
}

func getPassword() ([]byte, error) {
	fmt.Printf("Encryption password: ")
	defer fmt.Println()
	return term.ReadPassword(int(syscall.Stdin))
}

func getConfigPath() string {
	cfgPath := os.Getenv("GAUTH_CONFIG")
	if cfgPath == "" {
		user, err := user.Current()
		if err != nil {
			log.Fatal(err)
		}
		cfgPath = filepath.Join(user.HomeDir, ".config", "gauth.csv")
	}

	return cfgPath
}

func getUrls() []*otpauth.URL {
	cfgPath := getConfigPath()

	cfgContent, err := gauth.LoadConfigFile(cfgPath, getPassword)
	if err != nil {
		log.Fatalf("Loading config: %v", err)
	}

	urls, err := gauth.ParseConfig(cfgContent)
	if err != nil {
		log.Fatalf("Decoding configuration file: %v", err)
	}

	return urls
}

func printBareCode(accountName string, urls []*otpauth.URL) {
	for _, url := range urls {
		if strings.EqualFold(strings.ToLower(accountName), strings.ToLower(url.Account)) {
			_, curr, _, err := gauth.Codes(url)
			if err != nil {
				log.Fatalf("Generating codes for %q: %v", url.Account, err)
			}
			fmt.Print(curr)
			break
		}
	}
}

func printAllCodes(urls []*otpauth.URL) {
	_, progress := gauth.IndexNow() // TODO: do this per-code

	tw := tabwriter.NewWriter(os.Stdout, 0, 8, 1, ' ', 0)
	fmt.Fprintln(tw, "\tprev\tcurr\tnext")
	for _, url := range urls {
		prev, curr, next, err := gauth.Codes(url)
		if err != nil {
			log.Fatalf("Generating codes for %q: %v", url.Account, err)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", url.Account, prev, curr, next)
	}
	tw.Flush()
	fmt.Printf("[%-29s]\n", strings.Repeat("=", progress))
}
