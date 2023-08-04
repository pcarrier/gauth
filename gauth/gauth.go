// Package gauth implements the time-based OTP generation scheme used by Google
// Authenticator.
package gauth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"io/ioutil"
	"strings"
	"time"

	"github.com/creachadair/otp"
	"github.com/creachadair/otp/otpauth"
)

// IndexNow returns the current 30-second time step, and the number of seconds
// remaining until it ends.
func IndexNow() (uint64, int) {
	t := time.Now().Unix()
	return uint64(t / 30), int(t % 30)
}

// pickAlgorithm returns a constructor for the named hash function, or
// an error if the name is not a supported algorithm.
func pickAlgorithm(name string) (func() hash.Hash, error) {
	switch name {
	case "", "SHA1":
		return sha1.New, nil
	case "SHA256":
		return sha256.New, nil
	case "SHA512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %q", name)
	}
}

// Codes returns the previous, current, and next codes from u.
func Codes(u *otpauth.URL) (prev, curr, next string, _ error) {
	var ts uint64
	if u.Period > 0 {
		ts = otp.TimeWindow(u.Period)()
	} else {
		ts, _ = IndexNow()
	}
	return CodesAtTimeStep(u, ts)
}

// CodesAtTimeStep returns the previous, current, and next codes from u at the
// given time step value.
func CodesAtTimeStep(u *otpauth.URL, timeStep uint64) (prev, curr, next string, _ error) {
	if u.Type != "totp" {
		return "", "", "", fmt.Errorf("unsupported type: %q", u.Type)
	}

	alg, err := pickAlgorithm(u.Algorithm)
	if err != nil {
		return "", "", "", err
	}

	cfg := otp.Config{Hash: alg, Digits: u.Digits}
	if err := cfg.ParseKey(u.RawSecret); err != nil {
		return "", "", "", fmt.Errorf("invalid secret: %v", err)
	}
	prev = cfg.HOTP(timeStep - 1)
	curr = cfg.HOTP(timeStep)
	next = cfg.HOTP(timeStep + 1)
	return
}

// ReadConfigFile reads the config file at path and returns its contents and
// whether it is encrypted or not
func ReadConfigFile(path string) ([]byte, bool, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, false, err
	}

	if bytes.HasPrefix(data, []byte("Salted__")) {
		return data, true, nil // encrypted
	}

	return data, false, nil
}

// LoadConfigFile reads and decrypts, if necessary, the CSV config at path.
// The getPass function is called to obtain a password if needed.
func LoadConfigFile(path string, getPass func() ([]byte, error)) ([]byte, error) {
	data, isEncrypted, err := ReadConfigFile(path)

	if err != nil {
		return nil, err
	}

	if !isEncrypted {
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
	salting.Write(passwd)
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
	return rest[:len(rest)-pad], nil
}

// ParseConfig parses the contents of data as a gauth configuration file.  Each
// line of the file specifies a single configuration.
//
// The basic configuration format is:
//
//	name:secret
//
// where "name" is the site name and "secret" is the base32-encoded secret.
// This represents a default Google authenticator code with 6 digits and a
// 30-second refresh.
//
// Otherwise, a line must be a URL in the format:
//
//	otpauth://TYPE/LABEL?PARAMETERS
func ParseConfig(data []byte) ([]*otpauth.URL, error) {
	var out []*otpauth.URL
	for ln, line := range strings.Split(string(data), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue // skip blank lines
		}

		// URL format.
		if strings.HasPrefix(trim, "otpauth://") {
			u, err := otpauth.ParseURL(trim)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid otpauth URL: %v", ln+1, err)
			}
			out = append(out, u)
			continue
		}

		// Simple format (name:secret)
		parts := strings.SplitN(trim, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("line %d: invalid format (want name:secret)", ln+1)
		}
		out = append(out, &otpauth.URL{
			Type:      "totp",
			Account:   strings.TrimSpace(parts[0]),
			RawSecret: strings.TrimSpace(parts[1]),
		})
	}
	return out, nil
}
