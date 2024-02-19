// Copyright (C) 2019 Michael J. Fromberger. All Rights Reserved.

// Package otp generates single use authenticator codes using the HOTP or TOTP
// algorithms specified in RFC 4226 and RFC 6238 respectively.
//
// See https://tools.ietf.org/html/rfc4226, https://tools.ietf.org/html/rfc6238
package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"strconv"
	"strings"
	"time"
)

// DefaultTOTP generates a TOTP for the current time step using the default
// settings (compatible with Google Authenticator) based on the given key.
// An error is reported if the key is invalid.
func DefaultTOTP(key string) (string, error) {
	var std Config
	if err := std.ParseKey(key); err != nil {
		return "", err
	}
	return std.TOTP(), nil
}

// DefaultHOTP generates an HTOP for the specified counter using the default
// settings (compatible with Google Authenticator) based on the given key.
// An error is reported if the key is invalid.
func DefaultHOTP(key string, counter uint64) (string, error) {
	var std Config
	if err := std.ParseKey(key); err != nil {
		return "", err
	}
	return std.HOTP(counter), nil
}

// TimeWindow returns a time step generator that yields the number of n-second
// intervals elapsed at the current wallclock time since the Unix epoch.
func TimeWindow(n int) func() uint64 {
	return func() uint64 { return uint64(time.Now().Unix()) / uint64(n) }
}

var timeWindow30 = TimeWindow(30) // default 30-second window

// Config holds the settings that control generation of authentication codes.
// The only required field is Key. The other fields may be omitted, and will
// use default values compatible with the Google authenticator.
type Config struct {
	Key string // shared secret between server and user (required)

	Hash     func() hash.Hash // hash constructor (default is sha1.New)
	TimeStep func() uint64    // TOTP time step (default is TimeWindow(30))
	Counter  uint64           // HOTP counter value
	Digits   int              // number of OTP digits (default 6)

	// If set, this function is called with the counter hash to format a code of
	// the specified length. By default, the code is truncated per RFC 4226 and
	// formatted as decimal digits (0..9).
	//
	// If Format returns a string of the wrong length, code generation panics.
	Format func(hash []byte, length int) string
}

// ParseKey parses a base32 key using the top-level ParseKey function, and
// stores the result in c.
func (c *Config) ParseKey(s string) error {
	dec, err := ParseKey(s)
	if err != nil {
		return err
	}
	c.Key = string(dec)
	return nil
}

// ParseKey parses a key encoded as base32, the format used by common
// two-factor authentication setup tools. Whitespace is ignored, case is
// normalized, and padding is added if required.
func ParseKey(s string) ([]byte, error) {
	clean := strings.ToUpper(strings.Join(strings.Fields(s), ""))
	if n := len(clean) % 8; n != 0 {
		clean += "========"[:8-n]
	}
	return base32.StdEncoding.DecodeString(clean)
}

// HOTP returns the HOTP code for the specified counter value.
func (c Config) HOTP(counter uint64) string {
	nd := c.digits()
	code := c.format(c.hmac(counter), nd)
	if len(code) != nd {
		panic(fmt.Sprintf("invalid code length: got %d, want %d", len(code), nd))
	}
	return code
}

// Next increments the counter and returns the HOTP corresponding to its new value.
func (c *Config) Next() string { c.Counter++; return c.HOTP(c.Counter) }

// TOTP returns the TOTP code for the current time step.  If the current time
// step value is t, this is equivalent to c.HOTP(t).
func (c Config) TOTP() string {
	return c.HOTP(c.timeStepWindow())
}

func (c Config) newHash() func() hash.Hash {
	if c.Hash != nil {
		return c.Hash
	}
	return sha1.New
}

func (c Config) digits() int {
	if c.Digits <= 0 {
		return 6
	}
	return c.Digits
}

func (c Config) timeStepWindow() uint64 {
	if c.TimeStep != nil {
		return c.TimeStep()
	}
	return timeWindow30()
}

func (c Config) hmac(counter uint64) []byte {
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], uint64(counter))
	h := hmac.New(c.newHash(), []byte(c.Key))
	h.Write(ctr[:])
	return h.Sum(nil)
}

func (c Config) format(v []byte, nd int) string {
	if c.Format != nil {
		return c.Format(v, nd)
	}
	return formatDecimal(v, nd)
}

// Truncate truncates the specified digest using the algorithm from RFC 4226.
// Only the low-order 31 bits of the value are populated; the rest are zero.
//
// Note that RFC 6238 stipulates the same truncation algorithm regardless of
// the length of the chosen digest.
func Truncate(digest []byte) uint64 {
	offset := digest[len(digest)-1] & 0x0f
	code := (uint64(digest[offset]&0x7f) << 24) |
		(uint64(digest[offset+1]) << 16) |
		(uint64(digest[offset+2]) << 8) |
		(uint64(digest[offset+3]) << 0)
	return code
}

func formatDecimal(hash []byte, width int) string {
	const padding = "00000000000000000000"

	s := strconv.FormatUint(Truncate(hash), 10)
	if len(s) < width {
		s = padding[:width-len(s)] + s // left-pad with zeros
	}
	return s[len(s)-width:]
}

// FormatAlphabet constructs a formatting function that truncates the counter
// hash per RFC 4226 and assigns code digits using the letters of the given
// alphabet string.  Code digits are expanded from most to least significant.
func FormatAlphabet(alphabet string) func([]byte, int) string {
	if alphabet == "" {
		panic("empty formatting alphabet")
	}
	return func(hmac []byte, width int) string {
		code := Truncate(hmac)
		w := uint64(len(alphabet))
		out := make([]byte, width)
		for i := width - 1; i >= 0; i-- {
			out[i] = alphabet[int(code%w)]
			code /= w
		}
		return string(out)
	}
}
