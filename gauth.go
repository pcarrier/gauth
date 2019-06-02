package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/csv"
	"fmt"
	"io/ioutil"
	"log"
	"os/user"
	"path"
	"strings"
	"syscall"

	"github.com/pcarrier/gauth/gauth"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	user, e := user.Current()
	if e != nil {
		log.Fatal(e)
	}
	cfgPath := path.Join(user.HomeDir, ".config/gauth.csv")

	cfgContent, e := ioutil.ReadFile(cfgPath)
	if e != nil {
		log.Fatal(e)
	}

	// Support for 'openssl enc -aes-128-cbc -md sha256 -pass pass:'
	if bytes.HasPrefix(cfgContent, []byte("Salted__")) {
		fmt.Printf("Encryption password: ")
		passwd, e := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Printf("\n")
		if e != nil {
			log.Fatal(e)
		}
		salt := cfgContent[8:16]
		rest := cfgContent[16:]
		salting := sha256.New()
		salting.Write([]byte(passwd))
		salting.Write(salt)
		sum := salting.Sum(nil)
		key := sum[:16]
		iv := sum[16:]
		block, e := aes.NewCipher(key)
		if e != nil {
			log.Fatal(e)
		}

		mode := cipher.NewCBCDecrypter(block, iv)
		mode.CryptBlocks(rest, rest)
		// Remove padding
		i := len(rest) - 1
		for rest[i] < 16 {
			i--
		}
		cfgContent = rest[:i]
	}

	cfgReader := csv.NewReader(bytes.NewReader(cfgContent))
	// Unix-style tabular
	cfgReader.Comma = ':'

	cfg, e := cfgReader.ReadAll()
	if e != nil {
		log.Fatal(e)
	}

	currentTS, progress := gauth.IndexNow()
	prevTS := currentTS - 1
	nextTS := currentTS + 1

	wordSize := 0
	for _, record := range cfg {
		actualSize := len([]rune(record[0]))
		if actualSize > wordSize {
			wordSize = actualSize
		}
	}

	var header = "prev   curr   next"
	fmt.Println(leftPad(header, " ", wordSize+1))
	for _, record := range cfg {
		name := record[0]
		secret := normalizeSecret(record[1])
		prevToken := authCodeOrDie(secret, prevTS)
		currentToken := authCodeOrDie(secret, currentTS)
		nextToken := authCodeOrDie(secret, nextTS)
		fmt.Printf("%-*s %s %s %s\n", wordSize, name, prevToken, currentToken, nextToken)
	}
	fmt.Printf("[%-29s]\n", strings.Repeat("=", progress))
}

func leftPad(s string, padStr string, pLen int) string {
	return strings.Repeat(padStr, pLen) + s
}

// normalizeSecret cleans up whitespace and adds any missing padding to sec to
// use it as an OTP seed.
func normalizeSecret(sec string) string {
	noPadding := strings.ToUpper(strings.Replace(sec, " ", "", -1))
	padLength := 8 - (len(noPadding) % 8)
	if padLength < 8 {
		return noPadding + strings.Repeat("=", padLength)
	}
	return noPadding
}

// authCodeOrDie returns a code for the specified parameters, or aborts if an
// error occurred while generating the code.
func authCodeOrDie(sec string, ts int64) string {
	str, e := gauth.Code(sec, ts)
	if e != nil {
		log.Fatal(e)
	}
	return str
}
