package gauth_test

import (
	"bytes"
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

//go:generate openssl enc -aes-128-cbc -md sha256 -pass pass:x -in testdata/plaintext.csv -out testdata/encrypted.csv

func TestLoadConfig(t *testing.T) {

	// To update test data, edit testdata/plaintext.csv as desired,
	// then run go generate ./...
	// If you change the passphrase, update getPass below.
	//
	// For this test, the contents don't actually matter.

	var calledGetPass bool

	getPass := func() ([]byte, error) {
		calledGetPass = true
		return []byte("x"), nil
	}

	// Load the plaintext configuration file, and verify that we did not try to
	// decrypt its content.
	plain, err := gauth.LoadConfigFile("testdata/plaintext.csv", getPass)
	if err != nil {
		t.Fatalf("Loading plaintext config: %v", err)
	} else if calledGetPass {
		t.Error("Loading plaintext unexpectedly called getPass")
		calledGetPass = false
	}

	// Load the encrypted configuration file, and verify that we were able to
	// decrypt it successfully.
	enc, err := gauth.LoadConfigFile("testdata/encrypted.csv", getPass)
	if err != nil {
		t.Fatalf("Loading encrypted config: %v", err)
	} else if !calledGetPass {
		t.Error("Loading encrypted did not call getPass")
	}

	if !bytes.Equal(plain, enc) {
		t.Errorf("Decrypted not equal to plaintext:\ngot  %+v\nwant %+v", enc, plain)
	}
}
