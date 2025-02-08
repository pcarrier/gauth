package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/creachadair/otp/otpauth"
	"github.com/pcarrier/gauth/gauth"
	"golang.org/x/term"
)

type command struct {
	name        string
	shortFlag   string
	longFlags   []string
	description string
	handler     func(string, []*otpauth.URL)
}

var commands = []command{
	{
		name:        "bare",
		shortFlag:   "-b",
		longFlags:   []string{"-bare", "--bare"},
		description: "Print bare code for account",
		handler:     func(acc string, urls []*otpauth.URL) { printBareCode(acc, urls) },
	},
	{
		name:        "add",
		shortFlag:   "-a",
		longFlags:   []string{"-add", "--add"},
		description: "Add new account",
		handler:     func(acc string, _ []*otpauth.URL) { addCode(acc) },
	},
	{
		name:        "remove",
		shortFlag:   "-r",
		longFlags:   []string{"-remove", "--remove"},
		description: "Remove account",
		handler:     func(acc string, _ []*otpauth.URL) { removeCode(acc) },
	},
	{
		name:        "secret",
		shortFlag:   "-s",
		longFlags:   []string{"-secret", "--secret"},
		description: "Show secret for account",
		handler:     func(acc string, urls []*otpauth.URL) { printSecret(acc, urls) },
	},
}

var (
	cachedRaw  []byte
	cachedUrls []*otpauth.URL
)

func findCommand(arg string) *command {
	for i := range commands {
		if arg == commands[i].shortFlag {
			return &commands[i]
		}
		for _, f := range commands[i].longFlags {
			if arg == f {
				return &commands[i]
			}
		}
	}
	return nil
}

func printUsage() {
	fmt.Println("Usage: gauth [account] [command]")
	fmt.Println("\nCommands:")
	for _, cmd := range commands {
		flags := append([]string{cmd.shortFlag}, cmd.longFlags...)
		fmt.Printf("  %-25s %s\n", strings.Join(flags, ", "), cmd.description)
	}
	fmt.Println("\nExamples:")
	fmt.Println("  gauth                     # Show all codes")
	fmt.Println("  gauth github              # Show codes for an account (partial matches supported)")
	fmt.Println("  gauth github -b           # Show current code for an account")
	fmt.Println("  gauth github --add        # Add new account")
}

func isHelpFlag(arg string) bool {
	return arg == "-h" || arg == "--help"
}

func shouldShowHelp() bool {
	for _, a := range os.Args[1:] {
		if isHelpFlag(a) {
			return true
		}
	}
	cfgPath := getConfigPath()
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		if len(os.Args) > 2 {
			if cmd := findCommand(os.Args[2]); cmd != nil && cmd.name == "add" {
				return false
			}
		}
		fmt.Printf("No config file found at %s\n\n", cfgPath)
		return true
	}
	return false
}

func matchAccount(pattern, account string) bool {
	return strings.Contains(strings.ToLower(account), strings.ToLower(pattern))
}

func main() {
	if shouldShowHelp() {
		printUsage()
		return
	}

	var accountName string
	if len(os.Args) > 1 && !isHelpFlag(os.Args[1]) {
		accountName = os.Args[1]
	}

	var cmd *command
	if len(os.Args) > 2 {
		cmd = findCommand(os.Args[2])
	}

	if cmd != nil {
		var urls []*otpauth.URL
		if cmd.name != "add" {
			urls = getUrls()
		}
		cmd.handler(accountName, urls)
		return
	}

	printCodes(getUrls(), accountName)
}

func getPassword() ([]byte, error) {
	fmt.Print("Encryption password: ")
	defer fmt.Println()
	return term.ReadPassword(int(syscall.Stdin))
}

func getConfigPath() string {
	if cfg := os.Getenv("GAUTH_CONFIG"); cfg != "" {
		return cfg
	}
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Getting home directory: %v", err)
	}
	return filepath.Join(home, ".config", "gauth.csv")
}

func loadConfig() error {
	if cachedRaw != nil {
		return nil
	}

	cfgPath := getConfigPath()
	raw, err := gauth.LoadConfigFile(cfgPath, getPassword)
	if err != nil {
		return fmt.Errorf("loading config: %v", err)
	}

	urls, err := gauth.ParseConfig(raw)
	if err != nil {
		return fmt.Errorf("parsing config: %v", err)
	}

	cachedRaw = raw
	cachedUrls = urls
	return nil
}

func getUrls() []*otpauth.URL {
	if err := loadConfig(); err != nil {
		log.Fatal(err)
	}
	return cachedUrls
}

func getRawConfig() []byte {
	if err := loadConfig(); err != nil {
		log.Fatal(err)
	}
	return cachedRaw
}

func printBareCode(accountName string, urls []*otpauth.URL) {
	for _, url := range urls {
		if matchAccount(accountName, url.Account) {
			_, curr, _, err := gauth.Codes(url)
			if err != nil {
				log.Fatalf("Generating codes for %q: %v", url.Account, err)
			}
			fmt.Print(curr)
			return
		}
	}
}

func printSecret(accountName string, urls []*otpauth.URL) {
	for _, url := range urls {
		if matchAccount(accountName, url.Account) {
			fmt.Print(url.RawSecret)
			return
		}
	}
}

func addCode(accountName string) {
	cfgPath := getConfigPath()
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0700); err != nil {
		log.Fatalf("Creating config directory: %v", err)
	}

	password, err := handleEncryption(cfgPath)
	if err != nil && !os.IsNotExist(err) {
		log.Fatalf("Handling encryption: %v", err)
	}

	var rawConfig []byte
	if _, statErr := os.Stat(cfgPath); os.IsNotExist(statErr) {
		rawConfig = []byte("")
	} else {
		rawConfig = getRawConfig()
		if accountExists(accountName, rawConfig) {
			fmt.Printf("Account %q already exists. Nothing added.\n", accountName)
			return
		}
	}

	key := readNewKey(accountName)
	newConfig := updateConfig(string(rawConfig), accountName, key)
	if err := validateAndSaveConfig(cfgPath, password, newConfig, accountName); err != nil {
		log.Fatalf("Saving config: %v", err)
	}
	cachedRaw = nil
	cachedUrls = nil
}

func removeCode(accountName string) {
	cfgPath := getConfigPath()
	password, err := handleEncryption(cfgPath)
	if err != nil {
		log.Fatalf("Reading config: %v", err)
	}
	rawConfig := getRawConfig()
	newConfig, removed := buildNewConfig(accountName, rawConfig)
	if !removed {
		fmt.Printf("Account %q not found. Nothing removed.\n", accountName)
		return
	}
	if !confirmRemoval(accountName) {
		return
	}
	if err := gauth.WriteConfigFile(cfgPath, password, []byte(newConfig)); err != nil {
		log.Fatalf("Error writing config: %v", err)
	}
	cachedRaw = nil
	cachedUrls = nil
	fmt.Printf("%s has been removed.\n", accountName)
}

func buildNewConfig(accountName string, rawConfig []byte) (string, bool) {
	var builder strings.Builder
	removed := false
	for _, line := range strings.Split(string(rawConfig), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}
		parts := strings.SplitN(trim, ":", 2)
		if len(parts) > 0 {
			accName := strings.TrimSpace(parts[0])
			if matchAccount(accountName, accName) {
				removed = true
				continue
			}
		}
		builder.WriteString(trim)
		builder.WriteByte('\n')
	}
	return builder.String(), removed
}

func confirmRemoval(accountName string) bool {
	fmt.Printf("Are you sure you want to remove %s [y/N]: ", accountName)
	reader := bufio.NewReader(os.Stdin)
	resp, _ := reader.ReadString('\n')
	return strings.ToLower(strings.TrimSpace(resp)) == "y"
}

func updateConfig(currentConfig, accountName, key string) string {
	var builder strings.Builder
	builder.WriteString(strings.TrimSuffix(currentConfig, "\n"))
	builder.WriteByte('\n')
	builder.WriteString(accountName)
	builder.WriteByte(':')
	builder.WriteString(key)
	builder.WriteByte('\n')
	return builder.String()
}

func validateAndSaveConfig(cfgPath string, password []byte, newConfig, accountName string) error {
	parsedCfg, err := gauth.ParseConfig([]byte(newConfig))
	if err != nil {
		return fmt.Errorf("parsing new config: %v", err)
	}
	fmt.Printf("Current OTP for %s: ", accountName)
	printBareCode(accountName, parsedCfg)
	return gauth.WriteConfigFile(cfgPath, password, []byte(newConfig))
}

func accountExists(accountName string, rawConfig []byte) bool {
	for _, line := range strings.Split(string(rawConfig), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}
		parts := strings.SplitN(trim, ":", 2)
		if len(parts) < 2 {
			continue
		}
		if matchAccount(accountName, strings.TrimSpace(parts[0])) {
			return true
		}
	}
	return false
}

func handleEncryption(cfgPath string) ([]byte, error) {
	_, isEncrypted, err := gauth.ReadConfigFile(cfgPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if !isEncrypted {
		return nil, nil
	}
	pass, err := getPassword()
	if err != nil {
		return nil, fmt.Errorf("reading passphrase: %v", err)
	}
	return pass, nil
}

func printCodes(urls []*otpauth.URL, filter string) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 8, 1, ' ', 0)
	if _, err := fmt.Fprintln(tw, "\tprev\tcurr\tnext\tprog"); err != nil {
		log.Fatalf("Writing header: %v", err)
	}
	for _, url := range urls {
		if filter != "" && !matchAccount(filter, url.Account) {
			continue
		}
		prev, curr, next, err := gauth.Codes(url)
		if err != nil {
			log.Fatalf("Generating codes for %q: %v", url.Account, err)
		}
		period := url.Period
		if period == 0 {
			period = gauth.DefaultPeriod
		}
		elapsed := int(time.Now().Unix() % int64(period))
		progress := makeProgressBar(elapsed, period)
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", url.Account, prev, curr, next, progress); err != nil {
			log.Fatalf("Writing codes: %v", err)
		}
	}
	if err := tw.Flush(); err != nil {
		log.Fatalf("Flushing output: %v", err)
	}
}

func makeProgressBar(elapsed, period int) string {
	const width = 10
	filled := int(float64(elapsed) / float64(period) * float64(width))
	return "[" + strings.Repeat("=", filled) + strings.Repeat(" ", width-filled) + "]"
}

func readNewKey(accountName string) string {
	fmt.Printf("Key for %s: ", accountName)
	reader := bufio.NewReader(os.Stdin)
	key, _ := reader.ReadString('\n')
	return strings.TrimSpace(key)
}
