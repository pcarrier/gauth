package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
	"io"
	"io/ioutil"
	"strings"
)

// IsEncryptedPemFile take a filename and try to verify if it's a PEM format
// file. The function rely on x509.IsEncryptedPEMBlock() function and return a
// bool.
func IsEncryptedPemFile(file string) bool {
	fileBuf, err := ioutil.ReadFile(file)
	if err != nil {
		return false
	}

	pemBlockBuf, _ := pem.Decode(fileBuf)
	if pemBlockBuf == nil {
		return false
	}
	return x509.IsEncryptedPEMBlock(pemBlockBuf)
}

// AEADDecryptPEMBlock takes a password encrypted PEM block and the password used to
// encrypt it and returns a slice of decrypted DER encoded bytes. It inspects
// the DEK-Info header to determine the algorithm used for decryption. If no
// DEK-Info header is present, an error is returned. If an incorrect password
// is detected an IncorrectPasswordError is returned.
func AEADDecryptPEMBlock(b *pem.Block, password []byte) ([]byte, error) {
	AesHash := sha3.New256

	dek, ok := b.Headers["DEK-Info"]
	if !ok {
		return nil, errors.New("AEADDecryptPEMBlock: no DEK-Info header in block")
	}

	dekData := strings.Split(dek, ",")
	if len(dekData) != 3 {
		return nil, errors.New("AEADDecryptPEMBlock: malformed DEK-Info header")
	}

	hexNonce, hexSalt := dekData[1], dekData[2]
	nonce, err := hex.DecodeString(hexNonce)
	if err != nil {
		return nil, err
	}

	salt, err := hex.DecodeString(hexSalt)
	if err != nil {
		return nil, err
	}

	if len(salt) != 8 {
		return nil, errors.New("AEADDecryptPEMBlock: incorrect salt size")
	}

	/* let's PBKDF2 first.. */
	ourKey := pbkdf2.Key(password, salt, 16384, 32, AesHash)
	aesraw, err := aes.NewCipher(ourKey)
	if err != nil {
		return nil, errors.New("AEADEncryptPEMBlock: AES key setup failed: " + err.Error())
	}
	aesgcm, err := cipher.NewGCM(aesraw)
	if err != nil {
		return nil, errors.New("AEADEncryptPEMBlock: GCM failed: " + err.Error())
	}

	if len(nonce) != aesgcm.NonceSize() {
		return nil, errors.New("AEADDecryptPEMBlock: incorrect nonce size")
	}

	plaintext, err := aesgcm.Open(nil, nonce, b.Bytes, []byte(dek))
	if err != nil {
		return nil, errors.New("AEADDecryptPEMBlock: wrong parameters")
	}

	return plaintext, nil
}

// AEADEncryptPEMBlock returns a PEM block of the specified type holding the
// given DER-encoded data encrypted with AES-GCM256 algorithm, key is derived
// using PBKDF2 on the password.
// Header will be :
func AEADEncryptPEMBlock(rand io.Reader, blockType string, data, password []byte) (*pem.Block, error) {
	aesHash := sha3.New256

	salt := make([]byte, 8)
	_, err := io.ReadFull(rand, salt)
	if err != nil {
		return nil, errors.New("AEADEncryptPEMBlock: no rand: " + err.Error())
	}

	/* let's PBKDF2 first.. */
	ourKey := pbkdf2.Key(password, salt, 16384, 32, aesHash)
	aesraw, err := aes.NewCipher(ourKey)
	if err != nil {
		return nil, errors.New("AEADEncryptPEMBlock: AES key setup failed: " + err.Error())
	}
	aesgcm, err := cipher.NewGCM(aesraw)
	if err != nil {
		return nil, errors.New("AEADEncryptPEMBlock: GCM failed: " + err.Error())
	}

	/* this is our nonce */
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand, nonce); err != nil {
		return nil, errors.New("AEADEncryptPEMBlock: cannot generate Nonce: " + err.Error())
	}

	/* allocate data */
	//encrypted := make([]byte, len(data)+aesgcm.Overhead())

	/* this is our header aka ad */
	ourHeader := make(map[string]string)
	ourHeader["Proc-Type"] = "4,ENCRYPTED"
	ourHeader["DEK-Info"] = "AES-256-GCM" + "," + hex.EncodeToString(nonce) + "," + hex.EncodeToString(salt)

	/* encrypt & authenticate */
	encrypted := aesgcm.Seal(nil, nonce, data, []byte(ourHeader["DEK-Info"]))

	/* we're done. */
	return &pem.Block{
		Type:    blockType,
		Headers: ourHeader,
		Bytes:   encrypted,
	}, nil
}
