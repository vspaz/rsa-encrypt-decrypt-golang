package cryptolib

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/ascii85"
	"encoding/pem"
	"log"
)

type Decoder struct {
	PrivateKeyBlock *pem.Block
}

func NewDecoder(privateKey string) *Decoder {
	privateKeyBlock, _ := pem.Decode([]byte(privateKey))
	return &Decoder{
		PrivateKeyBlock: privateKeyBlock,
	}
}

func (d *Decoder) Decrypt(text []byte) string {
	var rsaPrivateKey *rsa.PrivateKey
	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(d.PrivateKeyBlock.Bytes)
	if err != nil {
		log.Fatal("Failed to load private key")
	}
	decryptedText, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, rsaPrivateKey, text, nil)
	if err != nil {
		log.Fatal("Failed to decrypt")
	}
	return string(decryptedText)
}

func (d Decoder) FromBase85(text string) []byte {
	decodedText := make([]byte, len([]byte(text)))
	decoded, _, _ := ascii85.Decode(decodedText, []byte(text), true)
	decodedText = decodedText[:decoded]
	//remove /x00 null bytes appended by ascii85
	return bytes.Trim(decodedText, "\x00")
}
