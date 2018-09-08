package seed128

import (
	"fmt"
	"testing"
)

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
	pdwRoundKey := SeedRoundKey(pbUserKey)

	// Encryption
	pbCipher := SeedEncrypt(pbData, pdwRoundKey)

	for i := 0; i < 16; i++ {
		fmt.Printf("%04x ", 0xff&pbUserKey[i])
	}
	fmt.Println()

	for i := 0; i < 16; i++ {
		fmt.Printf("%04x ", 0xff&pbData[i])
	}
	fmt.Println()

	for i := 0; i < 16; i++ {
		fmt.Printf("%04x ", 0xff&pbCipher[i])
	}
	fmt.Println()

	// Decryption
	pbPlain := SeedDecrypt(pbCipher, pdwRoundKey)

	for i := 0; i < 16; i++ {
		fmt.Printf("%04x ", 0xff&pbUserKey[i])
	}
	fmt.Println()

	for i := 0; i < 16; i++ {
		fmt.Printf("%04x ", 0xff&pbCipher[i])
	}
	fmt.Println()

	for i := 0; i < 16; i++ {
		fmt.Printf("%04x ", 0xff&pbPlain[i])
	}
	fmt.Println()

	if len(pbData) != len(pbPlain) {
		t.Error("len(pbData) != len(pbPlain)")
	}

	for i := range pbPlain {
		if pbData[i] != pbPlain[i] {
			t.Fatalf("pbData[%v] != pbPlain[%v]", i, i)
		}
	}
}
