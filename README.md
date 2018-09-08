# seed128
[![Build Status](https://travis-ci.org/geeksbaek/seed128.svg?branch=master)](https://travis-ci.org/geeksbaek/seed128)
[![codecov](https://codecov.io/gh/geeksbaek/seed128/branch/master/graph/badge.svg)](https://codecov.io/gh/geeksbaek/seed128)
[![Go Report Card](https://goreportcard.com/badge/github.com/geeksbaek/seed128)](https://goreportcard.com/report/github.com/geeksbaek/seed128)
[![GoDoc](https://godoc.org/github.com/geeksbaek/seed128?status.svg)](https://godoc.org/github.com/geeksbaek/seed128)

This package is an implementation of the SEED128 algorithm with Go. The original source is [here](https://seed.kisa.or.kr/iwt/ko/bbs/EgovReferenceDetail.do?bbsId=BBSMSTR_000000000002&nttId=34&pageIndex=1&searchCnd=&searchWrd=).

# What is SEED?

SEED is a block cipher developed by the Korea Internet & Security Agency (KISA). It is used broadly throughout South Korean industry, but seldom found elsewhere. It gained popularity in Korea because 40-bit encryption was not considered strong enough, so the Korea Information Security Agency developed its own standard. However, this decision has historically limited the competition of web browsers in Korea, as no major SSL libraries or web browsers supported the SEED algorithm, requiring users to use an ActiveX control in Internet Explorer for secure web sites.

On April 1, 2015 the Ministry of Science, ICT and Future Planning (MSIP) announced its plan to remove the ActiveX dependency from at least 90 percent of the country's top 100 websites by 2017. Instead, HTML5-based technologies will be employed as they operate on many platforms, including mobile devices. Starting with the private sector, the ministry plans to expand this further to ultimately remove this dependency from public websites as well.

[Read more from Wikipedia](https://en.wikipedia.org/wiki/SEED)

# Example

```go
encrypt := func(key []byte, message string) (encmess string, err error) {
    plainText := []byte(message)

    block, err := seed128.NewCipher(key)
    if err != nil {
        return
    }

    // IV needs to be unique, but doesn't have to be secure.
    // It's common to put it at the beginning of the ciphertext.
    cipherText := make([]byte, seed128.BlockSize+len(plainText))
    iv := cipherText[:seed128.BlockSize]
    if _, err = io.ReadFull(rand.Reader, iv); err != nil {
        return
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(cipherText[seed128.BlockSize:], plainText)

    // returns to base64 encoded string
    encmess = base64.URLEncoding.EncodeToString(cipherText)
    return
}

decrypt := func(key []byte, securemess string) (decodedmess string, err error) {
    cipherText, err := base64.URLEncoding.DecodeString(securemess)
    if err != nil {
        return
    }

    block, err := seed128.NewCipher(key)
    if err != nil {
        return
    }

    if len(cipherText) < seed128.BlockSize {
        err = errors.New("Ciphertext block size is too short!")
        return
    }

    // IV needs to be unique, but doesn't have to be secure.
    // It's common to put it at the beginning of the ciphertext.
    iv := cipherText[:seed128.BlockSize]
    cipherText = cipherText[seed128.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    // XORKeyStream can work in-place if the two arguments are the same.
    stream.XORKeyStream(cipherText, cipherText)

    decodedmess = string(cipherText)
    return
}

CIPHER_KEY := []byte("0123456789012345")
msg := "A quick brown fox jumped over the lazy dog."

if encrypted, err := encrypt(CIPHER_KEY, msg); err != nil {
    log.Println(err)
} else {
    log.Printf("CIPHER KEY: %s\n", string(CIPHER_KEY))
    log.Printf("ENCRYPTED: %s\n", encrypted)

    if decrypted, err := decrypt(CIPHER_KEY, encrypted); err != nil {
        log.Println(err)
    } else {
        log.Printf("DECRYPTED: %s\n", decrypted)
    }
}

// 2018/09/09 02:00:00 CIPHER KEY: 0123456789012345
// 2018/09/09 02:00:00 ENCRYPTED: 9VzqUQJh1JWmboAw_tfzzbHdaI8_53NHhBTFoNFPiPn4fqe_G44K0xQpYRyqRWAIp9ao-6OnTkJCh08=
// 2018/09/09 02:00:00 DECRYPTED: A quick brown fox jumped over the lazy dog.

```
