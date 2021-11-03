package cryptolib

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/ascii85"
	"encoding/pem"
	"log"
)

type Encoder struct {
	PublicKeyBlock *pem.Block
}

func NewEncoder(publicKey string) *Encoder {
	publicKeyBlock, _ := pem.Decode([]byte(publicKey))
	return &Encoder{
		PublicKeyBlock: publicKeyBlock,
	}
}

func (e *Encoder) Encrypt(text string) []byte {
	encodedText := []byte(text)
	var rsaPublicKey *rsa.PublicKey
	pub, err := x509.ParsePKIXPublicKey(e.PublicKeyBlock.Bytes)
	if err != nil {
		log.Fatal("Failed to load public key")
	}
	rsaPublicKey = pub.(*rsa.PublicKey)
	encryptedText, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, rsaPublicKey, encodedText, nil)
	if err != nil {
		log.Fatal("Failed to encrypt text with public key")
	}
	return encryptedText
}

func (e Encoder) ToBase85(text []byte) string {
	dest := make([]byte, ascii85.MaxEncodedLen(len(text)))
	ascii85.Encode(dest, text)
	return string(dest)
}
