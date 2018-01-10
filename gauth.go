package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/csv"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"log"
	"math/big"
	"os/user"
	"path"
	"strings"
	"syscall"
	"time"
	"os"
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

func PrintHeader() {
	fmt.Println("           prev   curr   next")
}

func PrintBar(progress int) {
	fmt.Printf("[%-29s]\n", strings.Repeat("=", progress))
}

func PrintRecord(record []string, currentTS int64) {
		prevTS := currentTS - 1
		nextTS := currentTS + 1
		name := record[0]
		secret := normalizeSecret(record[1])
		prevToken := authCodeOrDie(secret, prevTS)
		currentToken := authCodeOrDie(secret, currentTS)
		nextToken := authCodeOrDie(secret, nextTS)
		fmt.Printf("%-10s %s %s %s\n", name, prevToken, currentToken, nextToken)
}

func PrintRecordSecretOnly(record []string, currentTS int64) {
		secret := normalizeSecret(record[1])
		currentToken := authCodeOrDie(secret, currentTS)
		fmt.Printf("%s\n", currentToken)
}


func PrintAll(cfg [][]string)(){
	currentTS, progress := TimeStamp()
	PrintHeader()
	for _, record := range cfg {
			PrintRecord(record, currentTS)
	}
	PrintBar(progress)
}

func PrintSingle(cfg [][]string, name string) {
	currentTS, progress := TimeStamp()
	found := true
	for _, record := range cfg {
    if name == record[0] {
			if terminal.IsTerminal(int(os.Stdout.Fd())) {
				PrintHeader()
				PrintRecord(record, currentTS)
				PrintBar(progress)
			}else{
				PrintRecordSecretOnly(record, currentTS)
			}
    }
	}
	if !found {
		log.Fatalf("Token %s not found\n", name)
	}
}

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

	cfgReader := csv.NewReader(bytes.NewReader(cfgContent))
	// Unix-style tabular
	cfgReader.Comma = ':'

	cfg, e := cfgReader.ReadAll()
	if e != nil {
		log.Fatal(e)
	}

	if(len(os.Args) > 1){
		PrintSingle(cfg, os.Args[1])
	}else{
		PrintAll(cfg)
	}
}
