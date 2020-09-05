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
	privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAw0X5FPzMVlZB8t081QpG2Yw6zATdziAxQK0w+snzUKue8MVO
2xKDK04rTgKXntBRw0K8Lb7H6C00KAqiWCilJ6ApYQ+8BcY4zj3nEMFALANqtJfE
69C1XP+WWzsD/iuHYU9hilkeAk8S1YB679RL1+hD7DqIh0JDN7ST17buHsxvkxmI
pCIYwNmouJT4mH2cfs91x32zvHZ3eO/6my6rC7mpmWRY6ZLy2HMRiEUwqFWr2xbc
LlDiHqXVeMWjytrU6pTVMTfmeNem8/J5XkItyAR1AY79VH7q/Ft5uKB0GDLUswvw
x/Au35y6+4BskajOm82VI39UihUwcGFm8p9SuQIDAQABAoIBAQCQlmkePyjV7Lyc
JXB7lkZroseOdTP/Ahs19odDyvDclJb1VENVNtnk4NZzxruZnkpMOEe533+JzJ7H
30fh2wae1pqNAeeIpwM8wt0qrMzlSgpiedYXfcwsdhtQpdwJARYW2X4xwFbWAtLB
P4bHufwGfDZ+3cBl1oyK3Kxzl0GtjwlhAztt8g+NWBpna3codzb6Z2K0M5Wz4wFp
z8y4PXR57W/x3N0ICThbgTfWUfvJG/kUAT9kUIrtzo88qc4013AlsEtIAZksekYi
O1tRRvaYSxwAM/b+hl23Zbqwi8swIxfn/RLRac9pKq4G4bihPy0iPsBo3gM2fuAQ
SX3fe1BhAoGBAPegqqBuXpNwuciZXTsceH/rOwIq+KKXvv1RgZRW/OJ/0mvvaxpQ
cBVeFH+LE2/6+Lnn0TIZLnK41dTtLIw/RAVoq9zghYtG7vRgDNedo3bjzyenSqcc
mM6VV6n8O/FW1Gn73iBrcFeDjZn+4UGr2hf69rzlj2rdSr4g+S1iqTntAoGBAMng
J9U48+59KzK1Hftl+hQC1AQL/XRz4KFDL0UP4aesNga1DvmW8LQSZtMczmSU+Gc5
qr8fp3zhTfyVC9cuNCR9fKBxzR41ouuXyFAYM+V1BdpBQCb6jvf12OkT/B7Avqx+
35hCRCObWrXSeL5FArT5jZMlKTx3YYYj2B4qrPJ9AoGBAMJ49qeqJjJqzC0jbNm4
gVYM2jnYn42p2P++3CIwssf7FLlZvOZcl7ngOf70rV47Xs05psxOhHDqglyHq321
Telli9uapKZ+HbnkGRHYpoD/ZjhBJNrbFZLgLIm+IyFlTMqzWH5jgkXodfOj/SoD
GfPNT6uIKbsGceWhpa+kFTz9AoGASaBFJtDUtmBURvQjcTLqGC5H4Qn2cGhqvqXg
MZHvPNXkBmI2ifTw6NvlQI27AJgMWKmBip8i2LrbVImPffVN8xkJQQMASkpJlx8O
YZfSJZeegNFXcl/jkK/LYoZ1Z0nowMStC7zvWQUp+jI+8zX8HMD/T3E4LuNjYCbm
hWoPFYkCgYBYaSXWcNjxvQi+pQKACBU8NyyKa2yFFrxAEEUKT4zJ0PuBXUJtJfc1
qpu4KxBjFoeAlo91RTvoKAjq1rrPoCB0JKJhKc+JlDfqLFiIWbRytOQv/zXmlhgN
h8AAyT+/ZoBIYFtBT3OHOGDwrE6LZufo3Si39rWSw/CJkp8nVX3/+g==
-----END RSA PRIVATE KEY-----
`
)

func main() {
	publicKeyBlock, _ := pem.Decode([]byte(publicKey))
	privatKeyBlock, _ := pem.Decode([]byte(privateKey))
	enc := encryption.New(publicKeyBlock, privatKeyBlock, sha1.New())
	rsaEncryptedText := enc.EncryptWithPublicKey("foobarbaz")
	based85EncodedText := enc.ToBase85(rsaEncryptedText)
	log.Printf(based85EncodedText)
}
