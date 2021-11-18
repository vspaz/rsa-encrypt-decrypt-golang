# rsa-encrypt-decrypt-golang

a small library to encrypt/decrypt data with RSA public/private key pair and 
base64/85 encoding/decoding capabilities.

you can generate your own key pair as:

### Generating test public/private RSA key-pair.

```shell
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -out public.pem -pubout -outform PEM
```

### Usage example

```go
package main

const (
	testPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxGDcSAjiHKP9v2ITR+BjQmt9Tx2zW08ZyrjOxPew+Gxl2m5z
JyoP8sicZV81BeMNFkMg6q7sMtRXHhX1nFiTql5HBIqhZohYlN3LIXK2bdPWpDtt
rOFXfsSbZ4Wqy3XhXBhiPNn3kkkRv1N5L/IYcdrxwqaqvTlJzOeQnDsd3+AmkYst
uD4rgElOFkcUawtF7lKIYYFi42cYkJo51UD460mYieBezP6dZhFZB56pZ2rV8cQU
NrUQy2llpj+PxX/yhGnYI88ij0FST0gI2l4UsjtwXVB1Y2SxqrhNMdBU7W6ZA8WU
QQidr4MBxEFoujsLjaCl8LMsbEpAAilKezwubQIDAQABAoIBAFgkwbrzgcopMXP9
qXnRlbvyU0R3qFGLp5/+Y5C1PJHE1dK9UKJ7lrz6nnhBy6Lgzrb3Wob8DLij5pZy
dNPATkdiGa5IKznCaUAobUyOGKQjOWxt4ESAwKz9wmMs9ARu3MBhkXaOvzjB411l
Mjf7Ck3QYENmW6yjUiTOq3H0duxM/rn1Y88a9z2+aoWXQTltWvu0qKfb8SsqKzzx
HQFSalgNUxIqs+NoHRAT4ygzGGgipdP2/gXA966UonYuFAkpkutCeKVd7/6dMbm8
bgnr/x6ivGeLkbIaVkHNPRU+P4SYX1/XZohYIkTbggIih2aeH6+lEka8yZURANI6
HSUwLAECgYEA4bfavKu12NiIUO75/ZcqF8ojXq5+7HXP59t5X5MrURj2jizWs8YH
vPdrvYqxQNMZ0U0ZQBdAUWCn0Z11OXEak7YpKP78yoLIw2YnhgLVFvp3xZ+pIjjN
yidWbIvoq8SLMiUYHrMy3lMwVyFjM/AuA6bqNffCbHXqs9Ut+WnDN6ECgYEA3rlZ
S1gnE0sJrAJQ/5FnKgY/+TP6p+/k1SmRahNxYqpdP2t4CSwtYvjExRYcZefWFV1V
G04KvFuKf4p9zasYnISvWV735KU++li/QEw0LrVzXcnoRXiZwXauQzYQI6tuMYmc
NQRGBma3R7lQ/93YV3+hdubG+VCUsAC/B42zk00CgYAJ8zngQU2F3p27u50nkadY
Xx/KB7UupU7h8KncDbfGHmyX/eAFEsC6ksmcFGYV7nhf4p8vVRcPv0wGkINfYd4D
Du+nj/4Cy1sgSfuKC8vq9GWdP5mMGabwt2U26b/6+nIMZtg2Wj3u0Qn7fUxLONY+
cPg4ItDeSSBshwQ8z228oQKBgGyXL/s1OrAEaO3Nn1JLwWHS9EP7XN2ecBKiFr0C
R8kUSSyPqFHIkURtB/sTobrpww5dmA4dCcz2UNuIWXf6UKCXbKsFS5XWH5ONy4l8
3gBcBaiXtcCRYV3bEHHCnTHW9n3+mwOaVs3uLLQynVRzBHT8zGudbyvFZwk9A+aZ
5xENAoGBALO842ymiZmFYiv9CIdfBGFokbokQMci+4cJm4wWzxEiDjAzSglRHAei
/+oGBiPm8mKmx/dcU408x4PK76JlfduuoXuzE9jEmx46kwU4jGDS1GZYkwjGVPY8
8UmZ7fFkjNFJH0Rh5y+tmoFyou3FsWzL2lpd1mIryAH2LR3PGE/t
-----END RSA PRIVATE KEY-----
`
	testPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxGDcSAjiHKP9v2ITR+Bj
Qmt9Tx2zW08ZyrjOxPew+Gxl2m5zJyoP8sicZV81BeMNFkMg6q7sMtRXHhX1nFiT
ql5HBIqhZohYlN3LIXK2bdPWpDttrOFXfsSbZ4Wqy3XhXBhiPNn3kkkRv1N5L/IY
cdrxwqaqvTlJzOeQnDsd3+AmkYstuD4rgElOFkcUawtF7lKIYYFi42cYkJo51UD4
60mYieBezP6dZhFZB56pZ2rV8cQUNrUQy2llpj+PxX/yhGnYI88ij0FST0gI2l4U
sjtwXVB1Y2SxqrhNMdBU7W6ZA8WUQQidr4MBxEFoujsLjaCl8LMsbEpAAilKezwu
bQIDAQAB
-----END PUBLIC KEY-----
`
)
```

```go
package main

import (
    "log"
    "github.com/vspaz/rsa-encrypt-decrypt-golang/pkg/cryptolib"
)

func rsaEncryptDecrypt() {
	// example_1: Encrypt/Decrypt with RSA
	expectedText := "some expectedText goes here"
	encoder := cryptolib.NewEncoder(testPublicKey)
	rsaEncryptedText := encoder.Encrypt(expectedText)

	decoder := cryptolib.NewDecoder(testPrivateKey)
	rsaDecryptedText := decoder.Decrypt(rsaEncryptedText)

	if expectedText != rsaDecryptedText {
		log.Fatalln("failed to decrypt")
	}
}

```

```go
package main

import (
	"log"
	"github.com/vspaz/rsa-encrypt-decrypt-golang/pkg/cryptolib"
)

func rsaEncryptDecryptAndBase85Encode() {
	expectedText := "some expectedText goes here"

	// encoding example
	encoder := cryptolib.NewEncoder(testPublicKey)
	rsaEncodedText := encoder.Encrypt(text)
	base85EncodedText := encoder.ToBase85(rsaEncodedText)
	log.Println(base85EncodedText)

	// decoding example
	decoder := cryptolib.NewDecoder(testPrivateKey)
	base85decodedText := decoder.FromBase85(base85EncodedText)
	rsaDecodedText := decoder.Decrypt(base85decodedText)
	log.Println(rsaDecodedText) // ->  "some text data"
	if rsaDecodedText != expectedText {
		log.Fatalln("failed to decrypt")
	}
}
```

```go
package main

import (
	"github.com/vspaz/rsa-encrypt-decrypt-golang/pkg/cryptolib"
	"log"
)

func rsaEncryptDecryptAndBase64Encode() {
	expectedText := "some expectedText goes here"

	// encoding example
	encoder := cryptolib.NewEncoder(testPublicKey)
	rsaEncodedText := encoder.Encrypt(expectedText)
	base64EncodedText := encoder.ToBase64(rsaEncodedText)
	log.Println(base64EncodedText)

	// decoding example
	decoder := cryptolib.NewDecoder(testPrivateKey)
	base64decodedText := decoder.FromBase64(base64EncodedText)
	rsaDecodedText := decoder.Decrypt(base64decodedText)
	log.Println(rsaDecodedText) // ->  "some text data"
	if rsaDecodedText != expectedText {
		log.Fatalln("failed to decrypt")
	}
}
```

```go
package main

import (
	"github.com/vspaz/rsa-encrypt-decrypt-golang/pkg/cryptolib"
	"log"
)

func encodeDecodeWithBase85() {
	expectedText := "some expectedText goes here"
	encodedText := cryptolib.Encoder{}.ToBase85([]byte(expectedText))
	actualText := string(cryptolib.Decoder{}.FromBase85(encodedText))
	if actualText !=  expectedText {
		log.Fatalln("failed to decode")
    }
}
```

```go
package main

import (
	"github.com/vspaz/rsa-encrypt-decrypt-golang/pkg/cryptolib"
	"log"
)

func encodeDecodeWithBase64() {
	expectedText := "some expectedText goes here"
	encodedText := cryptolib.Encoder{}.ToBase64([]byte(expectedText))
	actualText := string(cryptolib.Decoder{}.FromBase64(encodedText))
	if actualText !=  expectedText {
		log.Fatalln("failed to decode")
    }
}
```

**NOTE**: please refer to [rsa-encrypt-decrypt-python](https://github.com/vspaz/rsa-encrypt-decrypt-python) if you need the Python lib.
