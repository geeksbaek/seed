package seed128

import (
	"testing"
)

type CryptTest struct {
	key []byte
	in  []byte
	out []byte
}

var encryptTests = []CryptTest{
	{
		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
		[]byte{0xad, 0x3f, 0x3c, 0xd6, 0x10, 0xc4, 0xf1, 0xfe, 0x45, 0x1f, 0x92, 0xc8, 0xb3, 0xc8, 0xf8, 0xe5},
	},
}

func Test(t *testing.T) {
	// User secret key
	pbUserKey := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	// input plaintext to be encrypted
	pbData := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	}

	// Derive roundkeys from user secret key
	pdwRoundKey := make([]uint32, 32)
	seedRoundKey(pbUserKey, pdwRoundKey)

	// Encryption
	pbCipher := make([]byte, 16)
	seedEncrypt(pdwRoundKey, pbCipher, pbData)

	// for i := 0; i < 16; i++ {
	// 	fmt.Printf("%02x ", pbUserKey[i])
	// }
	// fmt.Println()

	// for i := 0; i < 16; i++ {
	// 	fmt.Printf("%02x ", pbData[i])
	// }
	// fmt.Println()

	// for i := 0; i < 16; i++ {
	// 	fmt.Printf("%02x ", pbCipher[i])
	// }
	// fmt.Println()

	// Decryption
	pbPlain := make([]byte, 16)
	seedDecrypt(pdwRoundKey, pbPlain, pbCipher)

	// for i := 0; i < 16; i++ {
	// 	fmt.Printf("%02x ", pbUserKey[i])
	// }
	// fmt.Println()

	// for i := 0; i < 16; i++ {
	// 	fmt.Printf("%02x ", pbCipher[i])
	// }
	// fmt.Println()

	// for i := 0; i < 16; i++ {
	// 	fmt.Printf("%02x ", pbPlain[i])
	// }
	// fmt.Println()

	if len(pbData) != len(pbPlain) {
		t.Error("len(pbData) != len(pbPlain)")
	}

	for i := range pbPlain {
		if pbData[i] != pbPlain[i] {
			t.Fatalf("pbData[%v] != pbPlain[%v]", i, i)
		}
	}
}

func TestCipherEncrypt(t *testing.T) {
	for i, tt := range encryptTests {
		c, err := NewCipher(tt.key)
		if err != nil {
			t.Errorf("NewCipher(%d bytes) = %s", len(tt.key), err)
			continue
		}
		out := make([]byte, len(tt.in))
		c.Encrypt(out, tt.in)
		for j, v := range out {
			if v != tt.out[j] {
				t.Errorf("Cipher.Encrypt %d: out[%d] = %#x, want %#x", i, j, v, tt.out[j])
				break
			}
		}
	}
}

func TestCipherDecrypt(t *testing.T) {
	for i, tt := range encryptTests {
		c, err := NewCipher(tt.key)
		if err != nil {
			t.Errorf("NewCipher(%d bytes) = %s", len(tt.key), err)
			continue
		}
		plain := make([]byte, len(tt.in))
		c.Decrypt(plain, tt.out)
		for j, v := range plain {
			if v != tt.in[j] {
				t.Errorf("decryptBlock %d: plain[%d] = %#x, want %#x", i, j, v, tt.in[j])
				break
			}
		}
	}
}

func BenchmarkEncrypt(b *testing.B) {
	tt := encryptTests[0]
	c, err := NewCipher(tt.key)
	if err != nil {
		b.Fatal("NewCipher:", err)
	}
	out := make([]byte, len(tt.in))
	b.SetBytes(int64(len(out)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(out, tt.in)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	tt := encryptTests[0]
	c, err := NewCipher(tt.key)
	if err != nil {
		b.Fatal("NewCipher:", err)
	}
	out := make([]byte, len(tt.out))
	b.SetBytes(int64(len(out)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Decrypt(out, tt.out)
	}
}

func BenchmarkExpand(b *testing.B) {
	tt := encryptTests[0]
	n := len(tt.key) + 28
	c := &seed128Cipher{make([]uint32, n)}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seedRoundKey(tt.key, c.pdwRoundKey)
	}
}
