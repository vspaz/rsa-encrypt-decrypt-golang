package main

import (
	"crypto/sha1"
	"encoding/pem"
	"log"
	"rsa-encrypt-decrypt-golang/encryption"
)

const (
	publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw0X5FPzMVlZB8t081QpG
2Yw6zATdziAxQK0w+snzUKue8MVO2xKDK04rTgKXntBRw0K8Lb7H6C00KAqiWCil
J6ApYQ+8BcY4zj3nEMFALANqtJfE69C1XP+WWzsD/iuHYU9hilkeAk8S1YB679RL
1+hD7DqIh0JDN7ST17buHsxvkxmIpCIYwNmouJT4mH2cfs91x32zvHZ3eO/6my6r
C7mpmWRY6ZLy2HMRiEUwqFWr2xbcLlDiHqXVeMWjytrU6pTVMTfmeNem8/J5XkIt
yAR1AY79VH7q/Ft5uKB0GDLUswvwx/Au35y6+4BskajOm82VI39UihUwcGFm8p9S
uQIDAQAB
-----END PUBLIC KEY-----
`
)

func main() {
	publicKeyBlock, _ := pem.Decode([]byte(publicKey))
	enc := encryption.New(publicKeyBlock, sha1.New())
	rsaEncryptedText := enc.EncryptWithPublicKey("foobarbaz")
	based85EncodedText := enc.ToBase85(rsaEncryptedText)
	log.Printf(based85EncodedText)
}
