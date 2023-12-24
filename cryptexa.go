package cryptexa

import (
	"crypto/subtle"

	"github.com/coderero/go-cryptexa/tools"
	"golang.org/x/crypto/scrypt"
)

func HashOnly(password string, salt []byte, cost int, rounds int, parallelism int, dkLen int) ([]byte, error) {
	hash, err := scrypt.Key([]byte(password), salt, 1<<uint(cost), rounds, parallelism, dkLen)
	if err != nil {
		return nil, err
	}
	return hash, nil
}

func CompareHashOnly(password string, salt []byte, cost int, rounds int, parallelism int, dkLen int, hash []byte) (bool, error) {
	compareHash, err := HashOnly(password, salt, cost, rounds, parallelism, dkLen)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(hash, compareHash) == 1, nil
}

func GenerateHash(password string, params ...tools.HashParams) ([]byte, error) {
	var h tools.HashParams
	if len(params) > 0 {
		h = params[0]
	}
	h.CheckAndSetDefault()

	if h.Salt == nil {
		salt, err := tools.GenerateSaltBytes(h.SaltLength)
		if err != nil {
			return nil, err
		}
		h.Salt = salt
	}

	hash, err := HashOnly(password, h.Salt, h.Cost, h.Rounds, h.Parallelism, h.DKLen)

	if err != nil {
		return nil, err
	}

	hashByte, err := tools.GenerateWithParams(hash, h.Salt, h.Cost, h.Rounds, h.SaltLength, h.DKLen, h.Identifier, h.SaltSeprarator)
	if err != nil {
		return nil, err
	}

	return hashByte, nil

}
