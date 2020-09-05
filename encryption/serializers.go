package encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/ascii85"
	"encoding/pem"
	"hash"
	"log"
)

type Encryptor struct {
	PublicKeyBlock *pem.Block
	Hash           hash.Hash
}

func New(block *pem.Block, cryptoHash hash.Hash) *Encryptor {
	return &Encryptor{
		block,
		cryptoHash,
	}
}

func (enc *Encryptor) EncryptWithPublicKey(text string) []byte {
	randomReader := rand.Reader
	encodedPin := []byte(text)
	var rsaPublicKey *rsa.PublicKey
	pubInterface, parseErr := x509.ParsePKIXPublicKey(enc.PublicKeyBlock.Bytes)
	if parseErr != nil {
		log.Fatal("Failed to load public key")
	}
	rsaPublicKey = pubInterface.(*rsa.PublicKey)
	encryptedPin, encryptErr := rsa.EncryptOAEP(enc.Hash, randomReader, rsaPublicKey, encodedPin, nil)
	if encryptErr != nil {
		log.Fatal("Failed to encrypt text with public key")
	}
	return encryptedPin
}

func (enc *Encryptor) ToBase85(pin []byte) string {
	dest := make([]byte, ascii85.MaxEncodedLen(len(pin)))
	ascii85.Encode(dest, pin)
	return string(dest)
}
