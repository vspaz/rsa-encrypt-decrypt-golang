package encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/ascii85"
	"encoding/pem"
	"hash"
	"io"
	"log"
)

type CryptoObject struct {
	PublicKeyBlock  *pem.Block
	PrivateKeyBlock *pem.Block
	Hash            hash.Hash
	Random          io.Reader
}

func New(publicBlock *pem.Block, privateBlock *pem.Block, cryptoHash hash.Hash) *CryptoObject {
	return &CryptoObject{
		publicBlock,
		privateBlock,
		cryptoHash,
		rand.Reader,
	}
}

func (enc *CryptoObject) EncryptWithPublicKey(text string) []byte {
	encodedText := []byte(text)
	var rsaPublicKey *rsa.PublicKey
	pubInterface, parseErr := x509.ParsePKIXPublicKey(enc.PublicKeyBlock.Bytes)
	if parseErr != nil {
		log.Fatal("Failed to load public key")
	}
	rsaPublicKey = pubInterface.(*rsa.PublicKey)
	encryptedText, encryptErr := rsa.EncryptOAEP(enc.Hash, enc.Random, rsaPublicKey, encodedText, nil)
	if encryptErr != nil {
		log.Fatal("Failed to encrypt text with public key")
	}
	return encryptedText
}

func (enc *CryptoObject) ToBase85(text []byte) string {
	dest := make([]byte, ascii85.MaxEncodedLen(len(text)))
	ascii85.Encode(dest, text)
	return string(dest)
}

func (enc *CryptoObject) DecryptWithPrivateKey(text []byte) []byte {
	var pri *rsa.PrivateKey
	pri, err := x509.ParsePKCS1PrivateKey(enc.PrivateKeyBlock.Bytes)
	if err != nil {
		log.Fatal("Failed to load private key")
	}
	decryptedData, err := rsa.DecryptOAEP(enc.Hash, enc.Random, pri, text, nil)
	if err != nil {
		log.Fatal("Failed to decrypt")
	}
	return decryptedData
}

func (enc *CryptoObject) FromBase85(text []byte) string {
	return ""
}
