package jwtauth

import (
	"bytes"
	"errors"
	"testing"

	"github.com/dgrijalva/jwt-go"
)

func TestNewWithOptions(t *testing.T) {
	const alg = "RS256"
	testErr := errors.New("jwtauth test error")
	key1 := []byte("key1")
	key2 := []byte("key2")
	keyFunc := func(t *jwt.Token) (interface{}, error) {
		return nil, testErr
	}
	parser := jwt.Parser{}

	ja1 := NewWithOptions(alg)
	if ja1.parser == nil {
		t.Fatal("Parser not set!")
	}

	ja2 := NewWithOptions(alg, WithSignKey(key1), WithVerifyKey(key2),
		WithCustomParser(&parser), WithCustomKeyFunc(keyFunc))

	if key, _ := ja2.signKey.([]byte); key == nil || !bytes.Equal(key, key1) {
		t.Fatal("SignKey not set or set incorrectly!", key, key1)
	}

	if key, _ := ja2.verifyKey.([]byte); key == nil || !bytes.Equal(key, key2) {
		t.Fatal("VerifyKey not set or set incorrectly!", key, key2)
	}

	if ja2.parser != &parser {
		t.Fatal("Parser not set or set incorrectly!")
	}

	if _, err := ja2.keyFunc(nil); err != testErr {
		t.Fatal("CustomKeyFunc not set or set incorrectly!")
	}
}
