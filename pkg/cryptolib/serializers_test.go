package cryptolib

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestToBase85Ok(t *testing.T) {
	text := "foo"
	encodedText := CryptoObject{}.ToBase85([]byte(text));
	assert.Equal(t, "foo", string(CryptoObject{}.FromBase85(encodedText)))
}

