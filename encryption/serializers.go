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
	encodedText := []byte(text)
	var rsaPublicKey *rsa.PublicKey
	pubInterface, parseErr := x509.ParsePKIXPublicKey(enc.PublicKeyBlock.Bytes)
	if parseErr != nil {
		log.Fatal("Failed to load public key")
	}
	rsaPublicKey = pubInterface.(*rsa.PublicKey)
	encryptedText, encryptErr := rsa.EncryptOAEP(enc.Hash, randomReader, rsaPublicKey, encodedText, nil)
	if encryptErr != nil {
		log.Fatal("Failed to encrypt text with public key")
	}
	return encryptedText
}

func (enc *Encryptor) ToBase85(text []byte) string {
	dest := make([]byte, ascii85.MaxEncodedLen(len(text)))
	ascii85.Encode(dest, text)
	return string(dest)
}

func (enc *Encryptor) DecryptWithPrivateKey(text string) []byte {
	return nil
}

func (enc *Encryptor) FromBase85(text []byte) string {
	return ""
}
