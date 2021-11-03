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
	pubInterface, parseErr := x509.ParsePKIXPublicKey(e.PublicKeyBlock.Bytes)
	if parseErr != nil {
		log.Fatal("Failed to load public key")
	}
	rsaPublicKey = pubInterface.(*rsa.PublicKey)
	encryptedText, encryptErr := rsa.EncryptOAEP(sha1.New(), rand.Reader, rsaPublicKey, encodedText, nil)
	if encryptErr != nil {
		log.Fatal("Failed to encrypt text with public key")
	}
	return encryptedText
}

func (e Encoder) ToBase85(text []byte) string {
	dest := make([]byte, ascii85.MaxEncodedLen(len(text)))
	ascii85.Encode(dest, text)
	return string(dest)
}


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
