package cryptolib

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

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

func TestToBase85Ok(t *testing.T) {
	text := "foo"
	encodedText := Encoder{}.ToBase85([]byte(text))
	assert.Equal(t, "foo", string(Decoder{}.FromBase85(encodedText)))
}

func TestToBase64Ok(t *testing.T) {
	someString := "foobar"
	encodedText := Encoder{}.ToBase64([]byte(someString))
	assert.Equal(t, someString, string(Decoder{}.FromBase64(encodedText)))
}

func TestRsaEncryptDecrypt(t *testing.T) {
	expectedText := "some expectedText goes here"
	encoder := NewEncoder(testPublicKey)
	rsaEncryptedText := encoder.Encrypt(expectedText)

	decoder := NewDecoder(testPrivateKey)
	rsaDecryptedText := decoder.Decrypt(rsaEncryptedText)
	assert.Equal(t, expectedText, rsaDecryptedText)
}

func TestRsaEncryptDecryptWithPassword(t *testing.T) {
	publicKey := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9OUgjNr60cO7W8wcXZgw
4h9KQCBPyyiaMgahh4otlxct+GmeqNoa37jjshu0sN6GjpyMNG1rHvhKmjk8d1Tr
LBVQ9L7RSjjehGlV68kVOwdST1tvzXTaFQT/VrYCki44FlcaOiRiPqXdVceWVQOd
0hoWfBH2TzGPPlnOJtRxiMHD6iop9dUDF0zIxUqFVWHyGh/r6jrQeeUS8AbL0tTQ
/vtuR8TiWMM5lLA4+aZw8SoKbBXkuvfrOhrO2QvCsHk9UaJg/0Bguo4YVNnYt7gk
rJfUzyd141I29MankvYEEKtg1N2H+iRucJ+dy8ZbOcHs/YmwtinjJWVxXzuMLXLJ
HwIDAQAB
-----END PUBLIC KEY-----`
	expectedText := "some expectedText goes here"
	encoder := NewEncoder(publicKey)
	rsaEncryptedText := encoder.EncryptWithPassword(expectedText, "foobar")
	privateKey := `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIQTnoF86iXFUCAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAECBBAazFG0G/1Lf0S27g4dWECCBIIE
0EFQPL1OtkXIdiWeg2vGE1MV8HJ8r0eMAtvPNbxNOngGsOZEd3VQhm6NOGSqU7NT
yCaHNKd4FatOBMb8yFJU8sbDOKjnyVyYOaT3Lz1pGhUupw5OuSeKV2UTSoq743hd
IDNt9lwjz+Hn9RJLZW6Wyq4/aMwoL54j6n4EBAmS54MXZgxnxMgAvikeHLMDmlkb
I4GzKYUud/OKyJcesMnQbKW3H7czyeFgq2/6ocKv5wW+jOULgbMJdnIaKl8WRIRS
ZgrKgnlb6C5TAig4WHah6npOehZ3+bW9nfRmxrlp3NjpWfuO+l9uvoX/I8mLDXde
LaLz7SCQSw0DDwsJSfAWAiKRM2ZaXfEiND/g3za9v68y/r9r+YHlKsmwPE+9D2mr
L9gJ8MPYaOb+ngf8as2o9wE3WjYZkaaNE3ygrkkSKX+gw/GDc3puvf6dgPDzzmy4
zzLpxFpOqXEjqjBCO3kRD5hHIOJuftXEiYxc2rrQfei26V961O7Qr6857p0h0sxH
+cTfTzlmEKYk5mETzGT7gvjKEebQAQX3Ffi7LXCePUPSAco0Rw5kzPr8zLc6+Xii
0Qi+4Bh1rnKC03i7fmjwkpJOSM1l+Wer0WDpXVgkx9yZkZEqgHdzGfO+iDhKGYvX
PhdEHkhcvIVHBdQTTSbV0jb92aAG7Q6ctSQL7HTOC+CQV7msOtGzAx89hKXLkkSi
HNR3iSwqL8U3dXMrH6HEvCo0vKcotHjzskpK2CswZEKsYcZ5hbfIrcQCJ9/7Kvbi
IUihLVbkJsOx9qx+Gb2xwVYeqEleTPY1oAxK4equ31oupUsWjEyLecfUk4Y9WBd1
njQPDOECWEkm3RMWBYgqXlglKIzqixzyf0fD+7pitYVBdb4a+RsUIjRXBnvUjVie
n6ZFEyQY4ph62r3rbIFztTQJdMpdvZCYZGR+rigXWp8p6QzPlHI/wB4/Jb8ww7sW
nj7MCEuTgJPiRkL26qC7IWdsyWWZ+9zOm37grgTGj+1COcjPeS0rj8JQoAVCMI2h
ZrfhEKJhPzGEdB4PXUKjBIHJtT34k34dnZ4KruOF0PTD06fL+yXJCIsZ3yGqN/Tx
OXWFw/TF/9dBlgYMpiaXUS+ZFDcyj1zEvqZ3JKsDcffNIABwtmOP0Yr6geUfpPea
j2MSn+pe3X845nHDHBBC8kmliey8TyLTl9EtjNkSWzx5aMB1QbV3ehMEKKBSfn0v
AjkWYTvEqYE5p1ItPXz39T/ikAlMPrtrJUqrdDcs/7LHgeMLJT1Zv5vGr3k398GD
30INv907NNavhOV86U68JpRMEVHCi2e8xY9vhu/Ah+YTMx1DfF9jw2nnrmqr3LSe
/4NVBwSkM48iCNAfZ8M/sTEkXPHhQ8JwX3/MWpY8l5Ts3HZvfDM4TR+C0XJkiqkX
athmdaZ0uGWOR/BtG4EeZPznchacDrgUJwPTeHhDBuhnIIuc94UyLgmZ+XrD1jtO
d720IUmIoe2iCpd4pHN3mm27eLYWC6g3jpSP6EXQA2DztVcwhKm5CH3L40McZ9M3`
	decoder := NewDecoder(privateKey)
	rsaDecryptedText := decoder.DecryptWithPassword(rsaEncryptedText, "foobar")
	assert.Equal(t, expectedText, rsaDecryptedText)
}

func TestRsaEncodeDecodeAndBase85(t *testing.T) {
	expectedText := "some expectedText goes here"

	encoder := NewEncoder(testPublicKey)
	rsaEncryptedText := encoder.Encrypt(expectedText)
	base85EncodedText := encoder.ToBase85(rsaEncryptedText)

	decoder := NewDecoder(testPrivateKey)
	base85decodedText := decoder.FromBase85(base85EncodedText)
	actualText := decoder.Decrypt(base85decodedText)
	assert.Equal(t, expectedText, actualText)
}

func TestRsaEncryptDecryptAndBase64(t *testing.T) {
	expectedText := "some expectedText goes here"

	encoder := NewEncoder(testPublicKey)
	rsaEncryptedText := encoder.Encrypt(expectedText)
	base85EncodedText := encoder.ToBase64(rsaEncryptedText)

	decoder := NewDecoder(testPrivateKey)
	base85decodedText := decoder.FromBase64(base85EncodedText)
	actualText := decoder.Decrypt(base85decodedText)
	assert.Equal(t, expectedText, actualText)
}
