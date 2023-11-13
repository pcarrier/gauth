package main

import (
	"bufio"
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
	argument := ""

	if len(os.Args) > 1 {
		accountName = os.Args[1]
	}

	if len(os.Args) > 2 {
		if os.Args[2] == "-b" || os.Args[2] == "-bare" {
			argument = "bare"
		} else if os.Args[2] == "-a" || os.Args[2] == "-add" {
			argument = "add"
		} else if os.Args[2] == "-r" || os.Args[2] == "-remove" {
			argument = "remove"
		} else if os.Args[2] == "-s" || os.Args[2] == "-secret" {
			argument = "secret"
		}
	}

	if accountName != "" {
		switch argument {
		case "bare":
			printBareCode(accountName, getUrls())
			return
		case "add":
			addCode(accountName)
			return
		case "remove":
			removeCode(accountName)
			return
		case "secret":
			printSecret(accountName, getUrls())
			return
		default:
			printAllCodes(getUrls())
			return
		}
	}

	printAllCodes(getUrls())
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

func addCode(accountName string) {
	cfgPath := getConfigPath()

	// Check for encryption and ask for password if necessary
	_, isEncrypted, err := gauth.ReadConfigFile(cfgPath)

	if err != nil {
		log.Fatalf("Reading config: %v", err)
	}

	password, err := []byte(nil), nil

	if isEncrypted {
		password, err = getPassword()

		if err != nil {
			log.Fatalf("reading passphrase: %v", err)
		}
	}

	// Get decoded config
	rawConfig, err := gauth.LoadConfigFile(cfgPath, func() ([]byte, error) { return password, err })
	if err != nil {
		log.Fatalf("Loading config: %v", err)
	}

	newConfig := strings.TrimSuffix(string(rawConfig), "\n")

	// Check if account already exists
	for _, line := range strings.Split(newConfig, "\n") {
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(accountName)) {
			fmt.Printf("Account \"%s\" already exists. Nothing has been added.", accountName)
			return
		}
	}

	// Read new key
	fmt.Printf("Key for %s: ", accountName)
	reader := bufio.NewReader(os.Stdin)
	key, _ := reader.ReadString('\n')

	// Append new key
	newConfig += "\n" + accountName + ":" + key + "\n"

	// Try parsing the new config and print the current OTP
	parsedConfig, err := gauth.ParseConfig([]byte(newConfig))
	if err != nil {
		log.Fatalf("Parsing new config: %v", err)
	}

	fmt.Printf("Current OTP for %s: ", accountName)
	printBareCode(accountName, parsedConfig)

	// write new config
	err = gauth.WriteConfigFile(cfgPath, password, []byte(newConfig))
	if err != nil {
		log.Fatalf("Error writing new config: %v", err)
	}
}

func removeCode(accountName string) {
	cfgPath := getConfigPath()

	// Check for encryption and ask for password if necessary
	_, isEncrypted, err := gauth.ReadConfigFile(cfgPath)

	if err != nil {
		log.Fatalf("Reading config: %v", err)
	}

	password, err := []byte(nil), nil

	if isEncrypted {
		password, err = getPassword()

		if err != nil {
			log.Fatalf("Reading passphrase: %v", err)
		}
	}

	// Get decoded config
	rawConfig, err := gauth.LoadConfigFile(cfgPath, func() ([]byte, error) { return password, err })
	if err != nil {
		log.Fatalf("Loading config: %v", err)
	}

	newConfig := ""
	anythingRemoved := false

	// Iterate over config lines and search for the one to be removed
	for _, line := range strings.Split(string(rawConfig), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}

		if strings.HasPrefix(strings.ToLower(trim), strings.ToLower(accountName)) {
			anythingRemoved = true
			continue
		}

		newConfig += trim + "\n"

	}

	if !anythingRemoved {
		fmt.Printf("Account \"%s\" was not found. Nothing has been removed.", accountName)
		return
	}

	// Prompt for confirmation
	fmt.Printf("Are you sure you want to remove %s [y/N]: ", accountName)
	reader := bufio.NewReader(os.Stdin)
	confirmation, _ := reader.ReadString('\n')

	confirmation = strings.TrimSpace(confirmation)

	if strings.ToLower(confirmation) != "y" {
		return
	}

	// Write the new config
	err = gauth.WriteConfigFile(cfgPath, password, []byte(newConfig))
	if err != nil {
		log.Fatalf("Error writing new config: %v", err)
	}

	fmt.Printf("%s has been removed.", accountName)
}

func printSecret(accountName string, urls []*otpauth.URL) {
	for _, url := range urls {
		if strings.EqualFold(strings.ToLower(accountName), strings.ToLower(url.Account)) {
			fmt.Print(url.RawSecret)
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
