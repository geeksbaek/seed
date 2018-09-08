# seed

[![Build Status](https://travis-ci.org/geeksbaek/seed.svg?branch=master)](https://travis-ci.org/geeksbaek/seed)
[![codecov](https://codecov.io/gh/geeksbaek/seed/branch/master/graph/badge.svg)](https://codecov.io/gh/geeksbaek/seed)
[![Go Report Card](https://goreportcard.com/badge/github.com/geeksbaek/seed)](https://goreportcard.com/report/github.com/geeksbaek/seed)
[![GoDoc](https://godoc.org/github.com/geeksbaek/seed?status.svg)](https://godoc.org/github.com/geeksbaek/seed)

This package is an implements SEED encryption with Go. The original source is [here](https://seed.kisa.or.kr/iwt/ko/bbs/EgovReferenceDetail.do?bbsId=BBSMSTR_000000000002&nttId=34).

## What is SEED

SEED is a block cipher developed by the Korea Internet & Security Agency (KISA). It is used broadly throughout South Korean industry, but seldom found elsewhere. It gained popularity in Korea because 40-bit encryption was not considered strong enough, so the Korea Information Security Agency developed its own standard. However, this decision has historically limited the competition of web browsers in Korea, as no major SSL libraries or web browsers supported the SEED algorithm, requiring users to use an ActiveX control in Internet Explorer for secure web sites.

On April 1, 2015 the Ministry of Science, ICT and Future Planning (MSIP) announced its plan to remove the ActiveX dependency from at least 90 percent of the country's top 100 websites by 2017. Instead, HTML5-based technologies will be employed as they operate on many platforms, including mobile devices. Starting with the private sector, the ministry plans to expand this further to ultimately remove this dependency from public websites as well.

[Read more from Wikipedia](https://en.wikipedia.org/wiki/SEED)

## Disclaimer

Currently, only 128-bit encryption is supported. 256-bit encryption is under preparation.

Would you contribute?

## Example

```go
package main

import (
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "errors"
    "fmt"
    "io"

    "github.com/geeksbaek/seed"
)

func main() {
    CIPHER_KEY := []byte("0123456789012345")
    msg := "A quick brown fox jumped over the lazy dog."

    if encrypted, err := encrypt(CIPHER_KEY, msg); err != nil {
        fmt.Println(err)
    } else {
        fmt.Printf("CIPHER KEY: %s\n", string(CIPHER_KEY))
        fmt.Printf("ENCRYPTED: %s\n", encrypted)

        if decrypted, err := decrypt(CIPHER_KEY, encrypted); err != nil {
            fmt.Println(err)
        } else {
            fmt.Printf("DECRYPTED: %s\n", decrypted)
        }
    }

    // CIPHER KEY: 0123456789012345
    // ENCRYPTED: 9VzqUQJh1JWmboAw_tfzzbHdaI8_53NHhBTFoNFPiPn4fqe_G44K0xQpYRyqRWAIp9ao-6OnTkJCh08=
    // DECRYPTED: A quick brown fox jumped over the lazy dog.
}

func encrypt(key []byte, message string) (encmess string, err error) {
    plainText := []byte(message)

    block, err := seed.NewCipher(key)
    if err != nil {
        return
    }

    // IV needs to be unique, but doesn't have to be secure.
    // It's common to put it at the beginning of the ciphertext.
    cipherText := make([]byte, seed.BlockSize+len(plainText))
    iv := cipherText[:seed.BlockSize]
    if _, err = io.ReadFull(rand.Reader, iv); err != nil {
        return
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(cipherText[seed.BlockSize:], plainText)

    // returns to base64 encoded string
    encmess = base64.URLEncoding.EncodeToString(cipherText)
    return
}

func decrypt(key []byte, securemess string) (decodedmess string, err error) {
    cipherText, err := base64.URLEncoding.DecodeString(securemess)
    if err != nil {
        return
    }

    block, err := seed.NewCipher(key)
    if err != nil {
        return
    }

    if len(cipherText) < seed.BlockSize {
        err = errors.New("Ciphertext block size is too short!")
        return
    }

    // IV needs to be unique, but doesn't have to be secure.
    // It's common to put it at the beginning of the ciphertext.
    iv := cipherText[:seed.BlockSize]
    cipherText = cipherText[seed.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    // XORKeyStream can work in-place if the two arguments are the same.
    stream.XORKeyStream(cipherText, cipherText)

    decodedmess = string(cipherText)
    return
}
```

## Benchmark

It is a benchmark against the aes algorithm on laptops with i5-8250u.

```text
goos: windows
goarch: amd64
pkg: github.com/geeksbaek/seed
BenchmarkAESGCMSeal1K-8                  3000000               385 ns/op        2654.00 MB/s
BenchmarkSEED128GCMSeal1K-8                50000             27950 ns/op          36.64 MB/s
BenchmarkAESGCMOpen1K-8                  5000000               325 ns/op        3146.80 MB/s
BenchmarkSEED128GCMOpen1K-8                50000             27960 ns/op          36.62 MB/s
BenchmarkAESGCMSign8K-8                  1000000              1179 ns/op        6945.05 MB/s
BenchmarkSEED128GCMSign8K-8                30000             44199 ns/op         185.34 MB/s
BenchmarkAESGCMSeal8K-8                  1000000              2095 ns/op        3909.31 MB/s
BenchmarkSEED128GCMSeal8K-8                10000            234199 ns/op          34.98 MB/s
BenchmarkAESGCMOpen8K-8                  1000000              2272 ns/op        3604.85 MB/s
BenchmarkSEED128GCMOpen8K-8                 5000            247400 ns/op          33.11 MB/s
BenchmarkAESCFBEncrypt1K-8                500000              2658 ns/op         383.37 MB/s
BenchmarkSEED128CFBEncrypt1K-8             50000             24310 ns/op          41.92 MB/s
BenchmarkAESCFBDecrypt1K-8                500000              2644 ns/op         385.26 MB/s
BenchmarkSEED128CFBDecrypt1K-8             50000             24579 ns/op          41.46 MB/s
BenchmarkAESOFB1K-8                      1000000              1795 ns/op         567.69 MB/s
BenchmarkSEED128OFB1K-8                    50000             26129 ns/op          39.00 MB/s
BenchmarkAESCTR1K-8                      1000000              1800 ns/op         565.80 MB/s
BenchmarkSEED128CTR1K-8                    50000             22810 ns/op          44.67 MB/s
BenchmarkAESCBCEncrypt1K-8                500000              2542 ns/op         402.67 MB/s
BenchmarkSEED128CBCEncrypt1K-8             50000             26059 ns/op          39.29 MB/s
BenchmarkAESCBCDecrypt1K-8               1000000              2008 ns/op         509.95 MB/s
BenchmarkSEED128CBCDecrypt1K-8             50000             24119 ns/op          42.45 MB/s
PASS
ok      github.com/geeksbaek/seed    36.862s
```
