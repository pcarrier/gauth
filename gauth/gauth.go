// Package gauth implements the time-based OTP generation scheme used by Google
// Authenticator.
package gauth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/creachadair/otp"
)

// IndexNow returns the current 30-second time slice index, and the number of
// seconds remaining until it ends.
func IndexNow() (int64, int) {
	time := time.Now().Unix()
	return time / 30, int(time % 30)
}

// Codes returns the OTP codes for the given secret at the specified time slice
// and one slice on either side of it. It will report an error if the secret is
// not valid Base32.
func Codes(sec string, ts int64) (prev, curr, next string, _ error) {
	var cfg otp.Config
	if err := cfg.ParseKey(sec); err != nil {
		return "", "", "", err
	}
	prev = cfg.HOTP(uint64(ts - 1))
	curr = cfg.HOTP(uint64(ts))
	next = cfg.HOTP(uint64(ts + 1))
	return
}

// LoadConfigFile reads and decrypts, if necessary, the CSV config at path.
// The getPass function is called to obtain a password if needed.
func LoadConfigFile(path string, getPass func() ([]byte, error)) ([]byte, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if !bytes.HasPrefix(data, []byte("Salted__")) {
		return data, nil // not encrypted
	}

	// Support for 'openssl enc -aes-128-cbc -md sha256 -pass pass:'
	passwd, err := getPass()
	if err != nil {
		return nil, fmt.Errorf("reading passphrase: %v", err)
	}

	salt := data[8:16]
	rest := data[16:]
	salting := sha256.New()
	salting.Write([]byte(passwd))
	salting.Write(salt)
	sum := salting.Sum(nil)
	key := sum[:16]
	iv := sum[16:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %v", err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(rest, rest)

	// Remove CBC padding and verify that the key was valid.
	pad := int(rest[len(rest)-1])
	if pad == 0 || pad > len(rest) {
		return nil, errors.New("invalid decryption key")
	}
	for i := len(rest) - pad; i < len(rest); i++ {
		if int(rest[i]) != pad {
			return nil, errors.New("invalid block padding")
		}
	}
	return rest[:len(rest)-int(pad)], nil
}
