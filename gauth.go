package main

import (
	"bytes"
	//	"crypto/aes"
	//	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	//	"crypto/sha256"
	"encoding/base32"
	"encoding/csv"
	"encoding/pem"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"os/user"
	"path"
	"strings"
	"syscall"
	"time"
)

const (
	CONFIG_PLAIN = ".config/gauth.csv"
	CONFIG_PEM   = ".config/gauth.pem"

	HDR_PEM = "TOPT KEYFILE"

	// formatting
	HDR_ACCT = "account"
	HDR_PREV = "prev"
	HDR_NEXT = "next"
	HDR_CURR = "curr"
	HDR_FMT  = "%-10.10s %-6s %-6s %-6s\n"
)

func TimeStamp() (int64, int) {
	time := time.Now().Unix()
	return time / 30, int(time % 30)
}

func normalizeSecret(sec string) string {
	noPadding := strings.ToUpper(strings.Replace(sec, " ", "", -1))
	padLength := 8 - (len(noPadding) % 8)
	if padLength < 8 {
		return noPadding + strings.Repeat("=", padLength)
	}
	return noPadding
}

func AuthCode(sec string, ts int64) (string, error) {
	key, err := base32.StdEncoding.DecodeString(sec)
	if err != nil {
		return "", err
	}
	enc := hmac.New(sha1.New, key)
	msg := make([]byte, 8, 8)
	msg[0] = (byte)(ts >> (7 * 8) & 0xff)
	msg[1] = (byte)(ts >> (6 * 8) & 0xff)
	msg[2] = (byte)(ts >> (5 * 8) & 0xff)
	msg[3] = (byte)(ts >> (4 * 8) & 0xff)
	msg[4] = (byte)(ts >> (3 * 8) & 0xff)
	msg[5] = (byte)(ts >> (2 * 8) & 0xff)
	msg[6] = (byte)(ts >> (1 * 8) & 0xff)
	msg[7] = (byte)(ts >> (0 * 8) & 0xff)
	if _, err := enc.Write(msg); err != nil {
		return "", err
	}
	hash := enc.Sum(nil)
	offset := hash[19] & 0x0f
	trunc := hash[offset : offset+4]
	trunc[0] &= 0x7F
	res := new(big.Int).Mod(new(big.Int).SetBytes(trunc), big.NewInt(1000000))
	return fmt.Sprintf("%06d", res), nil
}

func authCodeOrDie(sec string, ts int64) string {
	str, e := AuthCode(sec, ts)
	if e != nil {
		log.Fatal(e)
	}
	return str
}

//
// default, try to open PEM file by default
// then try the PLAIN file, WARN if plain text.
//
// -e : encrypt gauth.csv to gauth.pem (or file config)
// if file already exist, ask for password, rencrypt/truncate with the same pass.
// if file does not exist, ask for password, verify password, create the new file.
//
// -d : decrypt gauth.pem to gauth.csv (or file config)
//

func main() {
	//var cfgPath string

	user, e := user.Current()
	if e != nil {
		log.Fatal(e)
	}
	/*
		cfgPath := path.Join(user.HomeDir, ".config/gauth.csv")

		cfgContent, e := ioutil.ReadFile(cfgPath)
		if e != nil {
			log.Fatal(e)
		}
	*/

	cfgPem := path.Join(user.HomeDir, CONFIG_PEM)
	cfgPlain := path.Join(user.HomeDir, CONFIG_PLAIN)

	statPlain, err := os.Stat(cfgPlain)
	statPem, err := os.Stat(cfgPem)

	// decrypt the file take the pem and generate a csv (truncate).
	decryptFlag := flag.Bool("d", false, "decrypt config file")
	// if the timestamp of csv is > pem and you can decrypt pem, then
	// reencrypt the csv and replace pem, otherwise fail.
	encryptFlag := flag.Bool("e", false, "encrypt config file")

	flag.Parse()

	// no config file ?!
	if statPlain == nil && statPem == nil {
		panic(fmt.Errorf("no topt token file present"))
	}

	// trying to encrypt and decrypt at the same time?!
	if *encryptFlag == true && *decryptFlag == true {
		cliErr := fmt.Errorf("-e and -d options are mutually exclusive")
		panic(cliErr)

	}

	if *decryptFlag == true && statPem != nil {
		// XXX do the decryption
		fmt.Printf("password: ")
		passwd, err := terminal.ReadPassword(syscall.Stdin)
		if err != nil {
			panic(err)
		}
		fmt.Printf("\n")

		cfgContent, err := ioutil.ReadFile(cfgPem)
		if err != nil {
			panic(err)
		}

		cfgPemBlock, _ := pem.Decode(cfgContent)
		if cfgPemBlock == nil || cfgPemBlock.Type != HDR_PEM {
			panic(fmt.Errorf("invalid PEM Block\n"))
		}

		cfgPlainContent, err := AEADDecryptPEMBlock(cfgPemBlock, passwd)
		if err != nil {
			panic(fmt.Errorf("invalid password\n"))
		}

		err = ioutil.WriteFile(cfgPlain, cfgPlainContent, 0600)
		if err != nil {
			panic(err)
		}

		os.Exit(0)

	}

	if *encryptFlag == true && statPlain != nil {
		// XXX do the encryption
		fmt.Printf("password: ")
		passwd, err := terminal.ReadPassword(syscall.Stdin)
		if err != nil {
			panic(err)
		}
		fmt.Printf("\n")

		// first decrypt and keep the passphrase
		if statPem != nil && IsEncryptedPemFile(cfgPem) == true {
			cfgPemContent, err := ioutil.ReadFile(cfgPem)
			if err != nil {
				panic(err)
			}

			cfgPemBlock, _ := pem.Decode(cfgPemContent)
			if cfgPemBlock == nil || cfgPemBlock.Type != HDR_PEM {
				panic(fmt.Errorf("invalid PEM Block\n"))
			}

			_, err = AEADDecryptPEMBlock(cfgPemBlock, passwd)
			if err != nil {
				panic(fmt.Errorf("invalid password\n"))
			}

		} else {

			fmt.Printf("retype password: ")
			rpasswd, err := terminal.ReadPassword(syscall.Stdin)
			if err != nil {
				panic(err)
			}
			fmt.Printf("\n")

			if bytes.Compare(passwd, rpasswd) != 0 {
				panic(fmt.Errorf("password don't match\n"))
			}
		}

		cfgPlainContent, err := ioutil.ReadFile(cfgPlain)
		if err != nil {
			panic(err)
		}

		// write the new file
		cfgContentBlock, err := AEADEncryptPEMBlock(rand.Reader, HDR_PEM, cfgPlainContent, passwd)
		if err != nil {
			panic(fmt.Errorf("encryption problem\n"))
		}

		cfgPemContent := pem.EncodeToMemory(cfgContentBlock)
		err = ioutil.WriteFile(cfgPem, cfgPemContent, 0600)
		if err != nil {
			panic(err)
		}

		os.Exit(0)

	} // end of if encryptFlag
	var cfgContent []byte

	// decrypt
	if statPem != nil && IsEncryptedPemFile(cfgPem) == true {
		fmt.Printf("password: ")
		passwd, err := terminal.ReadPassword(syscall.Stdin)
		if err != nil {
			panic(err)
		}
		fmt.Printf("\n")

		cfgPemContent, err := ioutil.ReadFile(cfgPem)
		if err != nil {
			panic(err)
		}

		cfgPemBlock, _ := pem.Decode(cfgPemContent)
		if cfgPemBlock == nil || cfgPemBlock.Type != HDR_PEM {
			panic(fmt.Errorf("invalid PEM Block\n"))
		}

		cfgContent, err = AEADDecryptPEMBlock(cfgPemBlock, passwd)
		if err != nil {
			panic(fmt.Errorf("invalid password\n"))
		}
	} else {
		cfgContent, err = ioutil.ReadFile(cfgPlain)
		if err != nil {
			panic(err)
		}
	}

	// Support for 'openssl enc -aes-128-cbc -md sha256 -pass pass:'
	/*
		if bytes.Compare(cfgContent[:8], []byte{0x53, 0x61, 0x6c, 0x74, 0x65, 0x64, 0x5f, 0x5f}) == 0 {
			fmt.Printf("Encryption password: ")
			passwd, e := terminal.ReadPassword(syscall.Stdin)
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
	*/

	cfgReader := csv.NewReader(bytes.NewReader(cfgContent))
	// Unix-style tabular
	cfgReader.Comma = ':'

	cfg, e := cfgReader.ReadAll()
	if e != nil {
		log.Fatal(e)
	}

	currentTS, progress := TimeStamp()
	prevTS := currentTS - 1
	nextTS := currentTS + 1

	//fmt.Println("           prev   curr   next")
	//fmt.Printf("%-10.10s %-6s %-6s %-6s\n", "account", "prev", "curr", "next")
	fmt.Printf(HDR_FMT, HDR_ACCT, HDR_PREV, HDR_CURR, HDR_NEXT)
	for _, record := range cfg {
		name := record[0]
		secret := normalizeSecret(record[1])
		prevToken := authCodeOrDie(secret, prevTS)
		currentToken := authCodeOrDie(secret, currentTS)
		nextToken := authCodeOrDie(secret, nextTS)
		//fmt.Printf("%-10.10s %-6s %-6s %-6s\n", name, prevToken, currentToken, nextToken)
		fmt.Printf(HDR_FMT, name, prevToken, currentToken, nextToken)
	}
	fmt.Printf("[%-29s]\n", strings.Repeat("=", progress))
}
