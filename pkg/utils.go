package pkg

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

var (
	// DefaultParams is the default hash parameters.
	DefaultParams = HashParams{
		Cost:        14,
		Rounds:      8,
		Parallelism: 1,
		SaltLength:  32,
		DKLen:       16,
		SignerKey:   "",
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
	if h.SignerKey == "" {
		h.SignerKey = DefaultParams.SignerKey
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

func SeprateHashParams(hash string) (string, string, HashParams, error) {
	var params HashParams

	if hash == "" {
		return "", "", params, errors.New("Err: It seems that you have not provided a hash to seprate")
	}

	d := strings.Split(hash, "$")
	if len(d) < 4 {
		return "", "", params, errors.New("Err: It seems that you have not provided a valid hash")
	}
	saltLen, err := strconv.Atoi(d[1])

	if err != nil {
		return "", "", params, errors.New("Err: It seems that you have not provided a valid hash")
	}

	cost, err := strconv.Atoi(d[2])
	if err != nil {
		return "", "", params, errors.New("Err: It seems that you have not provided a valid hash")
	}

	rounds, err := strconv.Atoi(d[3])
	if err != nil {
		return "", "", params, errors.New("Err: It seems that you have not provided a valid hash")
	}

	params = HashParams{
		Cost:       cost,
		Rounds:     rounds,
		SaltLength: saltLen,
	}

	salt := d[4][:saltLen]
	cipher := d[4][saltLen:]

	return salt, cipher, params, nil
}
