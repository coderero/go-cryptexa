package tools

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

var (
	DefaultParams = HashParams{
		Cost:        14,
		Rounds:      8,
		Parallelism: 1,
		SaltLength:  24,
		DKLen:       32,
		Identifier:  "c.1",
	}
)

func (h *HashParams) CheckAndSetDefault() {
	if h.Cost == 0 {
		h.Cost = DefaultParams.Cost
	}
	if h.Rounds == 0 {
		h.Rounds = DefaultParams.Rounds
	}
	if h.Parallelism == 0 {
		h.Parallelism = DefaultParams.Parallelism
	}
	if h.SaltLength == 0 {
		h.SaltLength = DefaultParams.SaltLength
	}
	if h.DKLen == 0 {
		h.DKLen = DefaultParams.DKLen
	}
	if h.Identifier == EmptyString {
		h.Identifier = DefaultParams.Identifier
	}
}

// The function generates a random byte array of a specified length or a default length if not
// provided.
func GenerateSaltBytes(saltLength ...int) ([]byte, error) {
	var length int
	if len(saltLength) > 0 {
		length = saltLength[0]
	} else {
		length = DefaultParams.SaltLength
	}

	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// The function encodes a byte slice using base64 encoding and returns the encoded string.
func Encode(cipher []byte) string {
	return base64.RawStdEncoding.EncodeToString(cipher)
}

// The function  decodes a given cipher string using base64 encoding and returns the decoded
// byte slice.
func Decode(cipher string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(cipher)
}

func GenerateWithParams(cipher, salt []byte, cost, rounds, saltlen, dklen int, identifier, seprator string) ([]byte, error) {
	cipherB64, saltB64 := Encode(cipher), Encode(salt)

	params := fmt.Sprintf("$%d$%d$%d$%d", cost, rounds, saltlen, dklen)

	paramsB64 := Encode([]byte(params))

	hash := fmt.Sprintf("$%s$%s$%s%s", identifier, paramsB64, saltB64, cipherB64)

	return []byte(hash), nil
}

func SeprateParams(hash string) (string, string, string, string, error) {
	var identifier, params, salt, cipher string

	identifier = hash[1:3]

	params = hash[4 : strings.Index(hash[4:], "$")+4]

	salt = hash[strings.Index(hash[4:], "$")+5 : strings.Index(hash[strings.Index(hash[4:], "$")+5:], "$")+strings.Index(hash[4:], "$")+5]

	cipher = hash[strings.Index(hash[strings.Index(hash[4:], "$")+5:], "$")+strings.Index(hash[4:], "$")+5:]

	return identifier, params, salt, cipher, nil
}
