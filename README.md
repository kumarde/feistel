# Feistel Cipher 
HMAC-SHA256 Feistel Cipher Implementation in Golang.

THIS IS HAND ROLLED CRYPTO RESEARCH CODE. USE AT YOUR OWN PERIL.

Library Usage
-------------

This code can be used as a library.

```go
import(
    "github.com/kumarde/feistel"
)

cipher := feistel.New()
msg = []byte{"This is a cool message that needs to be encrypted."}
cipher.Encrypt(msg)
```
