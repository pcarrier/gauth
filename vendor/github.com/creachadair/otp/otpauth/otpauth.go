// Copyright (C) 2020 Michael J. Fromberger. All Rights Reserved.

// Package otpauth handles the URL format used to specify OTP parameters.
//
// This package conforms to the specification at:
// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
//
// The general form of an OTP URL is:
//
//    otpauth://TYPE/LABEL?PARAMETERS
//
package otpauth

import (
	"encoding/base32"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/creachadair/otp"
)

const (
	defaultAlgorithm = "SHA1"
	defaultDigits    = 6
	defaultPeriod    = 30
)

// A URL contains the parsed representation of an otpauth URL.
type URL struct {
	Type      string // normalized to lowercase, e.g., "totp"
	Issuer    string // also called "provider" in some docs
	Account   string // without provider prefix
	RawSecret string // base32-encoded, no padding
	Algorithm string // normalized to uppercase; default is "SHA1"
	Digits    int    // default is 6
	Period    int    // in seconds; default is 30
	Counter   uint64
}

// Secret parses the contents of the RawSecret field.
func (u *URL) Secret() ([]byte, error) { return otp.ParseKey(u.RawSecret) }

// SetSecret encodes key as base32 and updates the RawSecret field.
func (u *URL) SetSecret(key []byte) {
	enc := base32.StdEncoding.EncodeToString(key)
	u.RawSecret = strings.TrimRight(enc, "=")
}

// String converts u to a URL in the standard encoding.
func (u *URL) String() string {
	var sb strings.Builder
	sb.WriteString("otpauth://")
	typ := strings.ToLower(u.Type)
	sb.WriteString(typ)
	sb.WriteByte('/')
	sb.WriteString(u.labelString())

	// Encode parameters if there are any non-default values.
	var params []string
	if a := strings.ToUpper(u.Algorithm); a != "" && a != "SHA1" {
		params = append(params, "algorithm="+url.PathEscape(a))
	}
	if c := u.Counter; c > 0 || typ == "hotp" {
		params = append(params, "counter="+strconv.FormatUint(c, 10))
	}
	if d := u.Digits; d > 0 && d != defaultDigits {
		params = append(params, "digits="+strconv.Itoa(d))
	}
	if o := u.Issuer; o != "" {
		params = append(params, "issuer="+url.PathEscape(o))
	}
	if p := u.Period; p > 0 && p != defaultPeriod {
		params = append(params, "period="+strconv.Itoa(p))
	}
	if s := u.RawSecret; s != "" {
		enc := strings.ToUpper(strings.Join(strings.Fields(strings.TrimRight(s, "=")), ""))
		params = append(params, "secret="+url.PathEscape(enc))
	}
	if len(params) != 0 {
		sb.WriteByte('?')
		sb.WriteString(strings.Join(params, "&"))
	}
	return sb.String()
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
// It expects its input to be a URL in the standard encoding.
func (u *URL) UnmarshalText(data []byte) error {
	p, err := ParseURL(string(data))
	if err != nil {
		return err
	}
	*u = *p // a shallow copy is safe, there are no pointers
	return nil
}

// MarshalText implemens the encoding.TextMarshaler interface.
// It emits the same URL string produced by the String method.
func (u *URL) MarshalText() ([]byte, error) {
	return []byte(u.String()), nil
}

func (u *URL) labelString() string {
	label := url.PathEscape(u.Account)
	if u.Issuer != "" {
		return url.PathEscape(u.Issuer) + ":" + label
	}
	return label
}

func (u *URL) parseLabel(s string) error {
	account, err := url.PathUnescape(s)
	if err != nil {
		return err
	}
	if i := strings.Index(account, ":"); i >= 0 {
		u.Issuer = strings.TrimSpace(account[:i])
		if u.Issuer == "" {
			return errors.New("empty issuer")
		}
		account = account[i+1:]
	}
	u.Account = strings.TrimSpace(account)
	if u.Account == "" {
		return errors.New("empty account name")
	}
	return nil
}

// ParseURL parses s as a URL in the otpauth scheme.
//
// The input may omit a scheme, but if present the scheme must be otpauth://.
// The parser will report an error for invalid syntax, including unknown URL
// parameters, but does not otherwise validate the results. In particular, the
// values of the Type and Algorithm fields are not checked.
//
// Fields of the URL corresponding to unset parameters are populated with
// default values as described on the URL struct. If a different issuer is set
// on the label and in the parameters, the parameter takes priority.
func ParseURL(s string) (*URL, error) {
	// A scheme is not required, but if present it must be "otpauth".
	if ps := strings.SplitN(s, "://", 2); len(ps) == 2 {
		if ps[0] != "otpauth" {
			return nil, fmt.Errorf("invalid scheme %q", ps[0])
		}
		s = ps[1] // trim scheme prefix
	}

	// Extract TYPE/LABEL and optional PARAMS.
	var typeLabel, params string
	if ps := strings.SplitN(s, "?", 2); len(ps) == 2 {
		typeLabel, params = ps[0], ps[1]
	} else {
		typeLabel = ps[0]
	}

	// Require that type and label are both present and non-empty.
	// Note that the "//" authority marker is treated as optional.
	ps := strings.SplitN(strings.TrimPrefix(typeLabel, "//"), "/", 2) // [TYPE, LABEL]
	if len(ps) != 2 || ps[0] == "" || ps[1] == "" {
		return nil, errors.New("invalid type/label")
	}

	out := &URL{
		Type:      strings.ToLower(ps[0]),
		Algorithm: defaultAlgorithm,
		Digits:    defaultDigits,
		Period:    defaultPeriod,
	}
	if err := out.parseLabel(ps[1]); err != nil {
		return nil, fmt.Errorf("invalid label: %v", err)
	}
	if params == "" {
		return out, nil
	}

	// Parse URL parameters.
	for _, param := range strings.Split(params, "&") {
		ps := strings.SplitN(param, "=", 2)
		if len(ps) == 1 {
			ps = append(ps, "") // check value below
		}
		value, err := url.PathUnescape(ps[1])
		if err != nil {
			return nil, fmt.Errorf("invalid value: %v", err)
		}

		// Handle string-valued parameters.
		if ps[0] == "algorithm" {
			out.Algorithm = strings.ToUpper(value)
			continue
		} else if ps[0] == "issuer" {
			out.Issuer = value
			continue
		} else if ps[0] == "secret" {
			out.RawSecret = value
			continue
		}

		// All other valid parameters require an integer argument.
		// Defer error reporting so we report an unknown field first.
		n, err := strconv.ParseUint(value, 10, 64)

		switch ps[0] {
		case "counter":
			out.Counter = n
		case "digits":
			out.Digits = int(n)
		case "period":
			out.Period = int(n)
		default:
			return nil, fmt.Errorf("invalid parameter %q", ps[0])
		}
		if err != nil {
			return nil, fmt.Errorf("invalid integer value %q", value)
		}
	}
	return out, nil
}
