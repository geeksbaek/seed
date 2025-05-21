package seed

// Common functions
func getB0(a uint32) uint32 { return 0x000000ff & (a) }
func getB1(a uint32) uint32 { return 0x000000ff & (a >> 8) }
func getB2(a uint32) uint32 { return 0x000000ff & (a >> 16) }
func getB3(a uint32) uint32 { return 0x000000ff & (a >> 24) }

// SEED round function
func seedRound(l0, l1, r0, r1 *uint32, k0, k1 uint32) {
	var t0, t1 uint32
	var t00, t11 uint64

	// F-function
	t0 = *r0 ^ k0
	t1 = *r1 ^ k1
	t1 ^= t0
	t00 = uint64(t0)
	t1 = ss0[getB0(t1)] ^ ss1[getB1(t1)] ^ ss2[getB2(t1)] ^ ss3[getB3(t1)]
	t11 = uint64(t1)
	t00 += t11
	t0 = ss0[getB0(uint32(t00))] ^ ss1[getB1(uint32(t00))] ^ ss2[getB2(uint32(t00))] ^ ss3[getB3(uint32(t00))]
	t00 = uint64(t0)
	t11 += t00
	t1 = ss0[getB0(uint32(t11))] ^ ss1[getB1(uint32(t11))] ^ ss2[getB2(uint32(t11))] ^ ss3[getB3(uint32(t11))]
	t11 = uint64(t1)
	t00 += t11

	// output of F function is added to left-side variable
	*l0 ^= uint32(t00)
	*l1 ^= uint32(t11)
}

func seedEncrypt(pdwRoundKey []uint32, dst, src []byte) {
	var l0, l1, r0, r1 uint32

	// Set up input values for encryption
	l0 = (uint32(src[0]) & 0x000000ff)
	l0 = (l0 << 8) ^ (uint32(src[1]) & 0x000000ff)
	l0 = (l0 << 8) ^ (uint32(src[2]) & 0x000000ff)
	l0 = (l0 << 8) ^ (uint32(src[3]) & 0x000000ff)

	l1 = (uint32(src[4]) & 0x000000ff)
	l1 = (l1 << 8) ^ (uint32(src[5]) & 0x000000ff)
	l1 = (l1 << 8) ^ (uint32(src[6]) & 0x000000ff)
	l1 = (l1 << 8) ^ (uint32(src[7]) & 0x000000ff)

	r0 = (uint32(src[8]) & 0x000000ff)
	r0 = (r0 << 8) ^ (uint32(src[9]) & 0x000000ff)
	r0 = (r0 << 8) ^ (uint32(src[10]) & 0x000000ff)
	r0 = (r0 << 8) ^ (uint32(src[11]) & 0x000000ff)

	r1 = (uint32(src[12]) & 0x000000ff)
	r1 = (r1 << 8) ^ (uint32(src[13]) & 0x000000ff)
	r1 = (r1 << 8) ^ (uint32(src[14]) & 0x000000ff)
	r1 = (r1 << 8) ^ (uint32(src[15]) & 0x000000ff)

	for i := 0; i < 16; i++ {
		k0 := pdwRoundKey[i*2]
		k1 := pdwRoundKey[i*2+1]
		seedRound(&l0, &l1, &r0, &r1, k0, k1)
		// Swap l0, l1 with r0, r1 for the next round, except for the last round
		if i < 15 {
			l0, l1, r0, r1 = r0, r1, l0, l1
		}
	}

	// Copying output values from last round to outData
	// After 16 rounds, the state is (L_16, R_16) stored in (r0, r1) and (l0, l1) respectively.
	// The original code output was (R_16, L_16).
	// Current r0, r1 hold L_16. Current l0, l1 hold R_16.
	for i := 0; i < 4; i++ {
		dst[i] = byte((l0 >> uint32(8*(3-i))) & 0xff)    // R_16 from current l0
		dst[4+i] = byte((l1 >> uint32(8*(3-i))) & 0xff)  // R_16 from current l1
		dst[8+i] = byte((r0 >> uint32(8*(3-i))) & 0xff)  // L_16 from current r0
		dst[12+i] = byte((r1 >> uint32(8*(3-i))) & 0xff) // L_16 from current r1
	}
	return
}

// Same as encrypt, except that round keys are applied in reverse order
func seedDecrypt(pdwRoundKey []uint32, dst []byte, src []byte) {
	var l0, l1, r0, r1 uint32

	// Set up input values for decryption
	// The input src is ciphertext.
	// Initial state for decryption: (L_cipher, R_cipher)
	l0 = (uint32(src[0]) & 0x000000ff)
	l0 = (l0 << 8) ^ (uint32(src[1]) & 0x000000ff)
	l0 = (l0 << 8) ^ (uint32(src[2]) & 0x000000ff)
	l0 = (l0 << 8) ^ (uint32(src[3]) & 0x000000ff)

	l1 = (uint32(src[4]) & 0x000000ff)
	l1 = (l1 << 8) ^ (uint32(src[5]) & 0x000000ff)
	l1 = (l1 << 8) ^ (uint32(src[6]) & 0x000000ff)
	l1 = (l1 << 8) ^ (uint32(src[7]) & 0x000000ff)

	r0 = (uint32(src[8]) & 0x000000ff)
	r0 = (r0 << 8) ^ (uint32(src[9]) & 0x000000ff)
	r0 = (r0 << 8) ^ (uint32(src[10]) & 0x000000ff)
	r0 = (r0 << 8) ^ (uint32(src[11]) & 0x000000ff)

	r1 = (uint32(src[12]) & 0x000000ff)
	r1 = (r1 << 8) ^ (uint32(src[13]) & 0x000000ff)
	r1 = (r1 << 8) ^ (uint32(src[14]) & 0x000000ff)
	r1 = (r1 << 8) ^ (uint32(src[15]) & 0x000000ff)

	for i := 0; i < 16; i++ {
		k0 := pdwRoundKey[30-(i*2)] // k0 is K_i1 in original decryption loop (corresponds to K_round_0 for seedRound)
		k1 := pdwRoundKey[31-(i*2)] // k1 is K_i0 in original decryption loop (corresponds to K_round_1 for seedRound)
		seedRound(&l0, &l1, &r0, &r1, k0, k1) // Corrected order: k0, k1
		// Swap l0, l1 with r0, r1 for the next round, except for the last round
		if i < 15 {
			l0, l1, r0, r1 = r0, r1, l0, l1
		}
	}

	// Copying output values from last round to outData
	// After 16 rounds of decryption, the state (L_0, R_0) is stored in (r0, r1) and (l0, l1) respectively.
	// This means r0, r1 contain the left half of the plaintext, and l0, l1 contain the right half.
	// The original decryption output was (L_0, R_0).
	for i := 0; i < 4; i++ {
		dst[i] = byte((r0 >> uint32(8*(3-i))) & 0xff)    // L_0 from current r0
		dst[4+i] = byte((r1 >> uint32(8*(3-i))) & 0xff)  // L_0 from current r1
		dst[8+i] = byte((l0 >> uint32(8*(3-i))) & 0xff)  // R_0 from current l0
		dst[12+i] = byte((l1 >> uint32(8*(3-i))) & 0xff) // R_0 from current l1
	}
	return
}

// Functions for Key schedule
// k parameter is a pointer to a 2-element array to store the two generated round keys.
// a, b, c, d are pointers to the parts of the main key being updated.
// z is the index for kc round constant.
func encRoundKeyUpdate0(k *[2]uint32, a, b, c, d *uint32, z int) {
	var t0, t00, t11 uint32 // Temporary variables for calculations
	t0 = *a                                          // Store original value of a
	*a = (((*a) >> 8) & 0x00ffffff) ^ (*b << 24)     // Update a: right shift a, XOR with left shifted b
	*b = (((*b) >> 8) & 0x00ffffff) ^ (t0 << 24)     // Update b: right shift b, XOR with left shifted original a
	t00 = (*a) + (*c) - (kc[z])                      // Calculate first part for G function input
	t11 = (*b) + (kc[z]) - (*d)                      // Calculate second part for G function input
	k[0] = ss0[getB0(t00)] ^ ss1[getB1(t00)] ^ ss2[getB2(t00)] ^ ss3[getB3(t00)] // Generate first round key
	k[1] = ss0[getB0(t11)] ^ ss1[getB1(t11)] ^ ss2[getB2(t11)] ^ ss3[getB3(t11)] // Generate second round key
}

func encRoundKeyUpdate1(k *[2]uint32, a, b, c, d *uint32, z int) {
	var t0, t00, t11 uint32 // Temporary variables for calculations
	t0 = *c                                                      // Store original value of c
	*c = (((*c) << 8) & 0xffffff00) ^ (((*d) >> 24) & 0x000000ff) // Update c: left shift c, XOR with right shifted d
	*d = (((*d) << 8) & 0xffffff00) ^ ((t0 >> 24) & 0x000000ff)   // Update d: left shift d, XOR with right shifted original c
	t00 = (*a) + (*c) - (kc[z])                                  // Calculate first part for G function input
	t11 = (*b) + (kc[z]) - (*d)                                  // Calculate second part for G function input
	k[0] = ss0[getB0(t00)] ^ ss1[getB1(t00)] ^ ss2[getB2(t00)] ^ ss3[getB3(t00)] // Generate first round key
	k[1] = ss0[getB0(t11)] ^ ss1[getB1(t11)] ^ ss2[getB2(t11)] ^ ss3[getB3(t11)] // Generate second round key
}

// Key Schedule
func seedRoundKey(pbUserKey []byte) []uint32 {
	var a, b, c, d uint32 // Variables to hold parts of the key
	var k [2]uint32        // Array to hold generated round keys from update functions
	var t0, t1 uint32      // Temporary variables for initial round key calculation
	nCount := 0            // Counter for storing round keys in pdwRoundKey

	// Set up input values for Key Schedule by converting byte key to uint32 parts
	a = (uint32(pbUserKey[0]) << 24) | (uint32(pbUserKey[1]) << 16) | (uint32(pbUserKey[2]) << 8) | uint32(pbUserKey[3])
	b = (uint32(pbUserKey[4]) << 24) | (uint32(pbUserKey[5]) << 16) | (uint32(pbUserKey[6]) << 8) | uint32(pbUserKey[7])
	c = (uint32(pbUserKey[8]) << 24) | (uint32(pbUserKey[9]) << 16) | (uint32(pbUserKey[10]) << 8) | uint32(pbUserKey[11])
	d = (uint32(pbUserKey[12]) << 24) | (uint32(pbUserKey[13]) << 16) | (uint32(pbUserKey[14]) << 8) | uint32(pbUserKey[15])

	pdwRoundKey := make([]uint32, 32) // Slice to store all 32 round keys

	// Calculate initial round keys (K1_0, K1_1)
	t0 = a + c - kc[0]
	t1 = b - d + kc[0]

	pdwRoundKey[nCount] = ss0[getB0(t0)] ^ ss1[getB1(t0)] ^ ss2[getB2(t0)] ^ ss3[getB3(t0)]
	nCount++
	pdwRoundKey[nCount] = ss0[getB0(t1)] ^ ss1[getB1(t1)] ^ ss2[getB2(t1)] ^ ss3[getB3(t1)]
	nCount++

	// Generate remaining round keys for rounds 2 through 16
	for i := 1; i <= 15; i++ { // Loop for KCi where i is from 1 to 15 (for rounds 2 to 16)
		if i%2 != 0 { // Odd round numbers (i.e., KC index 1, 3, 5... for rounds 2, 4, 6...)
			encRoundKeyUpdate0(&k, &a, &b, &c, &d, i) // Update rule for odd rounds in key schedule
		} else { // Even round numbers (i.e., KC index 2, 4, 6... for rounds 3, 5, 7...)
			encRoundKeyUpdate1(&k, &a, &b, &c, &d, i) // Update rule for even rounds in key schedule
		}
		pdwRoundKey[nCount] = k[0]
		nCount++
		pdwRoundKey[nCount] = k[1]
		nCount++
	}

	return pdwRoundKey
}
