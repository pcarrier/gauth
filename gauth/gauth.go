// Package gauth implements the time-based OTP generation scheme used by Google
// Authenticator.
package gauth

import (
	"time"

	"bitbucket.org/creachadair/otp"
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
