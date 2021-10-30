package cryptolib

import (
	"bytes"
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

func (crypto *CryptoObject) EncryptWithPublicKey(text string) []byte {
	encodedText := []byte(text)
	var rsaPublicKey *rsa.PublicKey
	pubInterface, parseErr := x509.ParsePKIXPublicKey(crypto.PublicKeyBlock.Bytes)
	if parseErr != nil {
		log.Fatal("Failed to load public key")
	}
	rsaPublicKey = pubInterface.(*rsa.PublicKey)
	encryptedText, encryptErr := rsa.EncryptOAEP(crypto.Hash, crypto.Random, rsaPublicKey, encodedText, nil)
	if encryptErr != nil {
		log.Fatal("Failed to encrypt text with public key")
	}
	return encryptedText
}


func (crypto *CryptoObject) DecryptWithPrivateKey(text []byte) string {
	var pri *rsa.PrivateKey
	pri, err := x509.ParsePKCS1PrivateKey(crypto.PrivateKeyBlock.Bytes)
	if err != nil {
		log.Fatal("Failed to load private key")
	}
	decryptedText, err := rsa.DecryptOAEP(crypto.Hash, crypto.Random, pri, text, nil)
	if err != nil {
		log.Fatal("Failed to decrypt")
	}
	return string(decryptedText)
}

func (crypto CryptoObject) ToBase85(text []byte) string {
	dest := make([]byte, ascii85.MaxEncodedLen(len(text)))
	ascii85.Encode(dest, text)
	return string(dest)
}

func (crypto CryptoObject) FromBase85(text string) []byte {
	decodedText := make([]byte, len([]byte(text)))
	decoded, _, _ := ascii85.Decode(decodedText, []byte(text), true)
	decodedText = decodedText[:decoded]
	//remove /x00 null bytes appended by ascii85
	return bytes.Trim(decodedText, "\x00")
}
