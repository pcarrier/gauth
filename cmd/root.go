package cmd

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
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "gauth",
	Short: "OTP codes from the commang line",
	Run: func(cmd *cobra.Command, args []string) {
		var accountName string
		if len(args) > 0 {
			accountName = args[0]
		}

		isBareCode, _ := cmd.Flags().GetBool("bare")

		urls := getUrls()

		if isBareCode && accountName != "" {
			printBareCode(accountName, urls)
		} else {
			printAllCodes(urls)
		}
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolP("bare", "b", false, "Print current code w/out table")
}

func getPassword() ([]byte, error) {
	fmt.Printf("Encryption password: ")
	defer fmt.Println()
	return term.ReadPassword(int(syscall.Stdin))
}

func getUrls() []*otpauth.URL {
	cfgPath := os.Getenv("GAUTH_CONFIG")
	if cfgPath == "" {
		user, err := user.Current()
		if err != nil {
			log.Fatal(err)
		}
		cfgPath = filepath.Join(user.HomeDir, ".config", "gauth.csv")
	}

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
			fmt.Println(curr)
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
