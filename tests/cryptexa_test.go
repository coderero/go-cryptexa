package test

import (
	"testing"

	"github.com/coderero/go-cryptexa"
	"github.com/coderero/go-cryptexa/tools"
)

func TestGenerateHash(t *testing.T) {
	password := "supersecret"
	salt, err := tools.GenerateSaltBytes(24)
	if err != nil {
		t.Error(err)
	}
	_, err = cryptexa.HashOnly(password, salt, 14, 8, 1, 32)
	if err != nil {
		t.Error(err)
	}
	t.Log("TEST_SUCCESS: Hash generated successfully")
}
