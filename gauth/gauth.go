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
	"os"
	"strings"

	"github.com/creachadair/otp"
	"github.com/creachadair/otp/otpauth"
)

const (
	saltedPrefix  = "Salted__"
	aesKeySize    = 16
	DefaultPeriod = 30
	blockSize     = 16
	saltOffset    = 8
	saltSize      = 8 // 16 - saltOffset
	minPadding    = 1
)

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
	if u.Period == 0 {
		u.Period = DefaultPeriod
	}
	ts = otp.TimeWindow(u.Period)()
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
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}

	if bytes.HasPrefix(data, []byte(saltedPrefix)) {
		return data, true, nil // encrypted
	}

	return data, false, nil
}

// LoadConfigFile reads and decrypts, if necessary, the CSV config at path.
// The getPass function is called to obtain a password if needed.
func LoadConfigFile(path string, getPass func() ([]byte, error)) ([]byte, error) {
	data, isEncrypted, err := ReadConfigFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %v", err)
	}

	if !isEncrypted {
		return data, nil
	}

	passwd, err := getPass()
	if err != nil {
		return nil, fmt.Errorf("reading passphrase: %v", err)
	}

	return decryptConfig(data, passwd)
}

// decryptConfig handles the decryption of encrypted configuration data
func decryptConfig(data, passwd []byte) ([]byte, error) {
	if len(data) < saltOffset+saltSize {
		return nil, errors.New("encrypted data too short")
	}

	salt := data[saltOffset : saltOffset+saltSize]
	rest := data[saltOffset+saltSize:]

	key, iv := deriveKeyAndIV(passwd, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %v", err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(rest, rest)

	return removePadding(rest)
}

// deriveKeyAndIV generates the key and IV from password and salt
func deriveKeyAndIV(passwd, salt []byte) (key, iv []byte) {
	salting := sha256.New()
	salting.Write(passwd)
	salting.Write(salt)
	sum := salting.Sum(nil)
	return sum[:blockSize], sum[blockSize:]
}

// removePadding removes and validates PKCS#7 padding
func removePadding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	pad := int(data[len(data)-1])
	if pad < minPadding || pad > blockSize || pad > len(data) {
		return nil, errors.New("invalid decryption key")
	}

	for i := len(data) - pad; i < len(data); i++ {
		if int(data[i]) != pad {
			return nil, errors.New("invalid block padding")
		}
	}

	return data[:len(data)-pad], nil
}

// WriteConfigFile encrypts the provided newConfig using passwd, if necessary,
// and writes it to path
func WriteConfigFile(path string, passwd []byte, newConfig []byte) error {
	data, isEncrypted, err := ReadConfigFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// If the file doesn't exist, treat it as non-encrypted
			isEncrypted = false
		} else {
			return fmt.Errorf("reading config file: %v", err)
		}
	}

	if !isEncrypted {
		return os.WriteFile(path, newConfig, 0600)
	}

	encryptedConfig, err := encryptConfig(data[8:16], passwd, newConfig)
	if err != nil {
		return fmt.Errorf("encrypting config: %v", err)
	}

	return os.WriteFile(path, encryptedConfig, 0600)
}

func encryptConfig(salt, passwd, config []byte) ([]byte, error) {
	salting := sha256.New()
	salting.Write(passwd)
	salting.Write(salt)
	sum := salting.Sum(nil)

	key := sum[:aesKeySize]
	iv := sum[aesKeySize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %v", err)
	}

	// Add padding
	padLength := blockSize - (len(config) % blockSize)
	paddedConfig := append(config, bytes.Repeat([]byte{byte(padLength)}, padLength)...)

	// Encrypt
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(paddedConfig, paddedConfig)

	// Construct final output
	return append([]byte(saltedPrefix+string(salt)), paddedConfig...), nil
}

// ParseConfig parses the contents of data as a gauth configuration file.
// Returns a slice of otpauth URLs representing the parsed configurations.
func ParseConfig(data []byte) ([]*otpauth.URL, error) {
	var out []*otpauth.URL
	lines := strings.Split(string(data), "\n")

	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}

		url, err := parseConfigLine(trim, i+1)
		if err != nil {
			return nil, err
		}

		if url != nil {
			out = append(out, url)
		}
	}
	return out, nil
}

// parseConfigLine parses a single line of configuration
func parseConfigLine(line string, lineNum int) (*otpauth.URL, error) {
	if strings.HasPrefix(line, "otpauth://") {
		u, err := otpauth.ParseURL(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: invalid otpauth URL: %v", lineNum, err)
		}
		return u, nil
	}

	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("line %d: invalid format (want name:secret)", lineNum)
	}

	return &otpauth.URL{
		Type:      "totp",
		Account:   strings.TrimSpace(parts[0]),
		RawSecret: strings.TrimSpace(parts[1]),
	}, nil
}
