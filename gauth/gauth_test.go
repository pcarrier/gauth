package gauth_test

import (
	"testing"

	"github.com/pcarrier/gauth/gauth"
)

func TestCodes(t *testing.T) {
	tests := []struct {
		secret string
		index  int64
		want   string
		fail   bool
	}{
		// Manually verified with the Google authenticator app.
		{"ABCDEFGH", 51790421, "305441", false},

		// Invalid Base32 input for the secret.
		{"blargh!", 123, "", true},
	}
	for _, test := range tests {
		_, got, _, err := gauth.Codes(test.secret, test.index)
		if err != nil && !test.fail {
			t.Errorf("Code(%q, %d): unexpected error: %v", test.secret, test.index, err)
		} else if got != test.want {
			t.Errorf("Code(%q, %d): got %q, want %q", test.secret, test.index, got, test.want)
		}
	}
}
