// Package gauth implements the time-based OTP generation scheme used by Google
// Authenticator.
package gauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"math/big"
	"time"
)

// IndexNow returns the current 30-second time slice index, and the number of
// seconds remaining until it ends.
func IndexNow() (int64, int) {
	time := time.Now().Unix()
	return time / 30, int(time % 30)
}

// Code returns the OTP code for the given secret at the specified time slice
// index. It will report an error if the secret is not valid Base32 or if HMAC
// generation fails.
func Code(sec string, ts int64) (string, error) {
	key, err := base32.StdEncoding.DecodeString(sec)
	if err != nil {
		return "", err
	}
	enc := hmac.New(sha1.New, key)
	msg := make([]byte, 8)
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
