package seed_test

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"

	seed "github.com/geeksbaek/seed"
)

func benchmarkAESGCMSign(b *testing.B, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var nonce [12]byte
	aes, _ := aes.NewCipher(key[:])
	aesgcm, _ := cipher.NewGCM(aes)
	var out []byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out = aesgcm.Seal(out[:0], nonce[:], nil, buf)
	}
}

func benchmarkSEED128GCMSign(b *testing.B, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var nonce [12]byte
	seed, _ := seed.NewCipher(key[:])
	seedgcm, _ := cipher.NewGCM(seed)
	var out []byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out = seedgcm.Seal(out[:0], nonce[:], nil, buf)
	}
}

func benchmarkAESGCMSeal(b *testing.B, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var nonce [12]byte
	var ad [13]byte
	aes, _ := aes.NewCipher(key[:])
	aesgcm, _ := cipher.NewGCM(aes)
	var out []byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out = aesgcm.Seal(out[:0], nonce[:], buf, ad[:])
	}
}

func benchmarkSEED128GCMSeal(b *testing.B, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var nonce [12]byte
	var ad [13]byte
	seed, _ := seed.NewCipher(key[:])
	seedgcm, _ := cipher.NewGCM(seed)
	var out []byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out = seedgcm.Seal(out[:0], nonce[:], buf, ad[:])
	}
}

func benchmarkAESGCMOpen(b *testing.B, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var nonce [12]byte
	var ad [13]byte
	aes, _ := aes.NewCipher(key[:])
	aesgcm, _ := cipher.NewGCM(aes)
	var out []byte
	out = aesgcm.Seal(out[:0], nonce[:], buf, ad[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := aesgcm.Open(buf[:0], nonce[:], out, ad[:])
		if err != nil {
			b.Errorf("Open: %v", err)
		}
	}
}

func benchmarkSEED128GCMOpen(b *testing.B, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var nonce [12]byte
	var ad [13]byte
	seed, _ := seed.NewCipher(key[:])
	seedgcm, _ := cipher.NewGCM(seed)
	var out []byte
	out = seedgcm.Seal(out[:0], nonce[:], buf, ad[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := seedgcm.Open(buf[:0], nonce[:], out, ad[:])
		if err != nil {
			b.Errorf("Open: %v", err)
		}
	}
}

func BenchmarkAESGCMSeal1K(b *testing.B) {
	benchmarkAESGCMSeal(b, make([]byte, 1024))
}

func BenchmarkSEED128GCMSeal1K(b *testing.B) {
	benchmarkSEED128GCMSeal(b, make([]byte, 1024))
}

func BenchmarkAESGCMOpen1K(b *testing.B) {
	benchmarkAESGCMOpen(b, make([]byte, 1024))
}

func BenchmarkSEED128GCMOpen1K(b *testing.B) {
	benchmarkSEED128GCMOpen(b, make([]byte, 1024))
}

func BenchmarkAESGCMSign8K(b *testing.B) {
	benchmarkAESGCMSign(b, make([]byte, 8*1024))
}

func BenchmarkSEED128GCMSign8K(b *testing.B) {
	benchmarkSEED128GCMSign(b, make([]byte, 8*1024))
}

func BenchmarkAESGCMSeal8K(b *testing.B) {
	benchmarkAESGCMSeal(b, make([]byte, 8*1024))
}

func BenchmarkSEED128GCMSeal8K(b *testing.B) {
	benchmarkSEED128GCMSeal(b, make([]byte, 8*1024))
}

func BenchmarkAESGCMOpen8K(b *testing.B) {
	benchmarkAESGCMOpen(b, make([]byte, 8*1024))
}

func BenchmarkSEED128GCMOpen8K(b *testing.B) {
	benchmarkSEED128GCMOpen(b, make([]byte, 8*1024))
}

// If we test exactly 1K blocks, we would generate exact multiples of
// the cipher's block size, and the cipher stream fragments would
// always be wordsize aligned, whereas non-aligned is a more typical
// use-case.
const almost1K = 1024 - 5

func BenchmarkAESCFBEncrypt1K(b *testing.B) {
	buf := make([]byte, almost1K)
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var iv [16]byte
	aes, _ := aes.NewCipher(key[:])
	ctr := cipher.NewCFBEncrypter(aes, iv[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctr.XORKeyStream(buf, buf)
	}
}

func BenchmarkSEED128CFBEncrypt1K(b *testing.B) {
	buf := make([]byte, almost1K)
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var iv [16]byte
	seed, _ := seed.NewCipher(key[:])
	ctr := cipher.NewCFBEncrypter(seed, iv[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctr.XORKeyStream(buf, buf)
	}
}

func BenchmarkAESCFBDecrypt1K(b *testing.B) {
	buf := make([]byte, almost1K)
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var iv [16]byte
	aes, _ := aes.NewCipher(key[:])
	ctr := cipher.NewCFBDecrypter(aes, iv[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctr.XORKeyStream(buf, buf)
	}
}

func BenchmarkSEED128CFBDecrypt1K(b *testing.B) {
	buf := make([]byte, almost1K)
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var iv [16]byte
	seed, _ := seed.NewCipher(key[:])
	ctr := cipher.NewCFBDecrypter(seed, iv[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctr.XORKeyStream(buf, buf)
	}
}

func BenchmarkAESOFB1K(b *testing.B) {
	buf := make([]byte, almost1K)
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var iv [16]byte
	aes, _ := aes.NewCipher(key[:])
	ctr := cipher.NewOFB(aes, iv[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctr.XORKeyStream(buf, buf)
	}
}

func BenchmarkSEED128OFB1K(b *testing.B) {
	buf := make([]byte, almost1K)
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var iv [16]byte
	seed, _ := seed.NewCipher(key[:])
	ctr := cipher.NewOFB(seed, iv[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctr.XORKeyStream(buf, buf)
	}
}

func BenchmarkAESCTR1K(b *testing.B) {
	buf := make([]byte, almost1K)
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var iv [16]byte
	aes, _ := aes.NewCipher(key[:])
	ctr := cipher.NewCTR(aes, iv[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctr.XORKeyStream(buf, buf)
	}
}

func BenchmarkSEED128CTR1K(b *testing.B) {
	buf := make([]byte, almost1K)
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var iv [16]byte
	seed, _ := seed.NewCipher(key[:])
	ctr := cipher.NewCTR(seed, iv[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctr.XORKeyStream(buf, buf)
	}
}

func BenchmarkAESCBCEncrypt1K(b *testing.B) {
	buf := make([]byte, 1024)
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var iv [16]byte
	aes, _ := aes.NewCipher(key[:])
	cbc := cipher.NewCBCEncrypter(aes, iv[:])
	for i := 0; i < b.N; i++ {
		cbc.CryptBlocks(buf, buf)
	}
}

func BenchmarkSEED128CBCEncrypt1K(b *testing.B) {
	buf := make([]byte, 1024)
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var iv [16]byte
	seed, _ := seed.NewCipher(key[:])
	cbc := cipher.NewCBCEncrypter(seed, iv[:])
	for i := 0; i < b.N; i++ {
		cbc.CryptBlocks(buf, buf)
	}
}

func BenchmarkAESCBCDecrypt1K(b *testing.B) {
	buf := make([]byte, 1024)
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var iv [16]byte
	aes, _ := aes.NewCipher(key[:])
	cbc := cipher.NewCBCDecrypter(aes, iv[:])
	for i := 0; i < b.N; i++ {
		cbc.CryptBlocks(buf, buf)
	}
}

func BenchmarkSEED128CBCDecrypt1K(b *testing.B) {
	buf := make([]byte, 1024)
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var iv [16]byte
	seed, _ := seed.NewCipher(key[:])
	cbc := cipher.NewCBCDecrypter(seed, iv[:])
	for i := 0; i < b.N; i++ {
		cbc.CryptBlocks(buf, buf)
	}
}
