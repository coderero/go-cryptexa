package main

import (
	"fmt"

	"github.com/coderero/go-cryptexa/pkg"
	"golang.org/x/crypto/scrypt"
)

var (
	name = "cryptexa"
)

type Params struct {
	HashKey    string
	HashParams pkg.HashParams
	Salt       []byte
}

func GenerateHash(password string, params ...Params) (string, error) {
	var p Params
	if len(params) > 0 {
		p = params[0]
	} else {
		p = Params{
			HashParams: pkg.DefaultParams,
		}
	}

	var salt []byte
	p.HashParams.CheckAndSetDefault()
	if p.Salt != nil {
		salt = p.Salt
	} else {
		b, err := pkg.GenerateSaltBytes(p.HashParams.SaltLength)
		if err != nil {
			return "", err
		}
		salt = b
	}

	cipher, err := scrypt.Key([]byte(password), salt, 1<<uint(p.HashParams.Cost), p.HashParams.Rounds, p.HashParams.Parallelism, p.HashParams.DKLen)
	if err != nil {
		return "", err
	}
	encodedCipher := pkg.Encode(cipher)
	encodedSalt := pkg.Encode(salt)

	var HashKey string
	if p.HashKey != "" {
		HashKey = p.HashKey
	} else {
		HashKey = name
	}

	storeable := fmt.Sprintf("$%s$%d$%d$%d$%s%s", HashKey, len(salt), p.HashParams.Cost, p.HashParams.Rounds, encodedSalt, encodedCipher)
	return storeable, nil
}
