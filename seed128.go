package seed128

import (
	"crypto/cipher"
	"strconv"
)

type seed128Cipher struct {
	pdwRoundKey []uint32
}

type KeySizeError int

func (k KeySizeError) Error() string {
	return "github.com/geeksbaek/seed128: invalid key size " + strconv.Itoa(int(k))
}

func NewCipher(key []byte) (cipher.Block, error) {
	k := len(key)
	switch k {
	default:
		return nil, KeySizeError(k)
	case 16:
		break
	}
	return newCipherGeneric(key)
}

func newCipherGeneric(key []byte) (cipher.Block, error) {
	n := len(key) + 28
	c := seed128Cipher{make([]uint32, n)}
	seedRoundKey(key, c.pdwRoundKey)
	return &c, nil
}

func (c *seed128Cipher) BlockSize() int { return BlockSize }

func (c *seed128Cipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("github.com/geeksbaek/seed128: input not full block")
	}
	if len(dst) < BlockSize {
		panic("github.com/geeksbaek/seed128: output not full block")
	}
	// if subtle.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
	// 	panic("github.com/geeksbaek/seed128: invalid buffer overlap")
	// }
	seedEncrypt(c.pdwRoundKey, dst, src)
}

func (c *seed128Cipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("github.com/geeksbaek/seed128: input not full block")
	}
	if len(dst) < BlockSize {
		panic("github.com/geeksbaek/seed128: output not full block")
	}
	// if subtle.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
	// 	panic("github.com/geeksbaek/seed128: invalid buffer overlap")
	// }
	seedDecrypt(c.pdwRoundKey, dst, src)
}
