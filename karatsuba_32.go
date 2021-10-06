package ed448

//c = a * b
func karatsubaMul(c, a, b *bigNumber) *bigNumber {

	var aa0 dword = dword(a[0]) + dword(a[8])
	var aa1 dword = dword(a[1]) + dword(a[9])
	var aa2 dword = dword(a[2]) + dword(a[10])
	var aa3 dword = dword(a[3]) + dword(a[11])
	var aa4 dword = dword(a[4]) + dword(a[12])
	var aa5 dword = dword(a[5]) + dword(a[13])
	var aa6 dword = dword(a[6]) + dword(a[14])
	var aa7 dword = dword(a[7]) + dword(a[15])
	var bb0 dword = dword(b[0]) + dword(b[8])
	var bb1 dword = dword(b[1]) + dword(b[9])
	var bb2 dword = dword(b[2]) + dword(b[10])
	var bb3 dword = dword(b[3]) + dword(b[11])
	var bb4 dword = dword(b[4]) + dword(b[12])
	var bb5 dword = dword(b[5]) + dword(b[13])
	var bb6 dword = dword(b[6]) + dword(b[14])
	var bb7 dword = dword(b[7]) + dword(b[15])


	var z0, z1, z2 dword

	//j = 0
	z2 = 0
	z2 += dword(a[0]) * dword(b[0])
	z1 += aa0 * bb0
	z1 -= z2
	z0 += dword(a[8]) * dword(b[8])
	z0 += z2

	z2 = 0
	z2 += aa7 * bb1
	z2 += aa6 * bb2
	z2 += aa5 * bb3
	z2 += aa4 * bb4
	z2 += aa3 * bb5
	z2 += aa2 * bb6
	z2 += aa1 * bb7

	z1 += dword(a[15]) * dword(b[9])
	z1 += dword(a[14]) * dword(b[10])
	z1 += dword(a[13]) * dword(b[11])
	z1 += dword(a[12]) * dword(b[12])
	z1 += dword(a[11]) * dword(b[13])
	z1 += dword(a[10]) * dword(b[14])
	z1 += dword(a[9]) * dword(b[15])
	z1 += z2

	z0 -= dword(a[7]) * dword(b[1])
	z0 -= dword(a[6]) * dword(b[2])
	z0 -= dword(a[5]) * dword(b[3])
	z0 -= dword(a[4]) * dword(b[4])
	z0 -= dword(a[3]) * dword(b[5])
	z0 -= dword(a[2]) * dword(b[6])
	z0 -= dword(a[1]) * dword(b[7])
	z0 += z2

	c[0] = word(z0) & radixMask
	c[8] = word(z1) & radixMask

	z0 >>= 28
	z1 >>= 28

	//j = 1
	z2 = 0
	z2 += dword(a[1]) * dword(b[0])
	z2 += dword(a[0]) * dword(b[1])

	z1 += aa1 * bb0
	z1 += aa0 * bb1
	z1 -= z2

	z0 += dword(a[9]) * dword(b[8])
	z0 += dword(a[8]) * dword(b[9])
	z0 += z2

	z2 = 0

	z2 += aa7 * bb2
	z2 += aa6 * bb3
	z2 += aa5 * bb4
	z2 += aa4 * bb5
	z2 += aa3 * bb6
	z2 += aa2 * bb7

	z1 += dword(a[15]) * dword(b[10])
	z1 += dword(a[14]) * dword(b[11])
	z1 += dword(a[13]) * dword(b[12])
	z1 += dword(a[12]) * dword(b[13])
	z1 += dword(a[11]) * dword(b[14])
	z1 += dword(a[10]) * dword(b[15])
	z1 += z2

	z0 -= dword(a[7]) * dword(b[2])
	z0 -= dword(a[6]) * dword(b[3])
	z0 -= dword(a[5]) * dword(b[4])
	z0 -= dword(a[4]) * dword(b[5])
	z0 -= dword(a[3]) * dword(b[6])
	z0 -= dword(a[2]) * dword(b[7])
	z0 += z2

	c[1] = word(z0) & radixMask
	c[9] = word(z1) & radixMask

	z0 >>= 28
	z1 >>= 28

	//j = 2
	z2 = 0
	z2 += dword(a[2]) * dword(b[0])
	z2 += dword(a[1]) * dword(b[1])
	z2 += dword(a[0]) * dword(b[2])

	z1 += aa2 * bb0
	z1 += aa1 * bb1
	z1 += aa0 * bb2
	z1 -= z2

	z0 += dword(a[10]) * dword(b[8])
	z0 += dword(a[9]) * dword(b[9])
	z0 += dword(a[8]) * dword(b[10])
	z0 += z2

	z2 = 0
	z2 += aa7 * bb3
	z2 += aa6 * bb4
	z2 += aa5 * bb5
	z2 += aa4 * bb6
	z2 += aa3 * bb7

	z1 += dword(a[15]) * dword(b[11])
	z1 += dword(a[14]) * dword(b[12])
	z1 += dword(a[13]) * dword(b[13])
	z1 += dword(a[12]) * dword(b[14])
	z1 += dword(a[11]) * dword(b[15])
	z1 += z2

	z0 -= dword(a[7]) * dword(b[3])
	z0 -= dword(a[6]) * dword(b[4])
	z0 -= dword(a[5]) * dword(b[5])
	z0 -= dword(a[4]) * dword(b[6])
	z0 -= dword(a[3]) * dword(b[7])
	z0 += z2

	c[2] = word(z0) & radixMask
	c[10] = word(z1) & radixMask

	z0 >>= 28
	z1 >>= 28

	//j = 3
	z2 = 0
	z2 += dword(a[3]) * dword(b[0])
	z2 += dword(a[2]) * dword(b[1])
	z2 += dword(a[1]) * dword(b[2])
	z2 += dword(a[0]) * dword(b[3])

	z1 += aa3 * bb0
	z1 += aa2 * bb1
	z1 += aa1 * bb2
	z1 += aa0 * bb3
	z1 -= z2

	z0 += dword(a[11]) * dword(b[8])
	z0 += dword(a[10]) * dword(b[9])
	z0 += dword(a[9]) * dword(b[10])
	z0 += dword(a[8]) * dword(b[11])
	z0 += z2

	z2 = 0
	z2 += aa7 * bb4
	z2 += aa6 * bb5
	z2 += aa5 * bb6
	z2 += aa4 * bb7

	z0 -= dword(a[7]) * dword(b[4])
	z0 -= dword(a[6]) * dword(b[5])
	z0 -= dword(a[5]) * dword(b[6])
	z0 -= dword(a[4]) * dword(b[7])
	z0 += z2

	z1 += dword(a[15]) * dword(b[12])
	z1 += dword(a[14]) * dword(b[13])
	z1 += dword(a[13]) * dword(b[14])
	z1 += dword(a[12]) * dword(b[15])
	z1 += z2

	c[3] = word(z0) & radixMask
	c[11] = word(z1) & radixMask

	z0 >>= 28
	z1 >>= 28

	//j = 4
	z2 = 0
	z2 += dword(a[4]) * dword(b[0])
	z2 += dword(a[3]) * dword(b[1])
	z2 += dword(a[2]) * dword(b[2])
	z2 += dword(a[1]) * dword(b[3])
	z2 += dword(a[0]) * dword(b[4])

	z1 += aa4 * bb0
	z1 += aa3 * bb1
	z1 += aa2 * bb2
	z1 += aa1 * bb3
	z1 += aa0 * bb4
	z1 -= z2

	z0 += dword(a[12]) * dword(b[8])
	z0 += dword(a[11]) * dword(b[9])
	z0 += dword(a[10]) * dword(b[10])
	z0 += dword(a[9]) * dword(b[11])
	z0 += dword(a[8]) * dword(b[12])
	z0 += z2

	z2 = 0
	z2 += aa7 * bb5
	z2 += aa6 * bb6
	z2 += aa5 * bb7

	z1 += dword(a[15]) * dword(b[13])
	z1 += dword(a[14]) * dword(b[14])
	z1 += dword(a[13]) * dword(b[15])
	z1 += z2

	z0 -= dword(a[7]) * dword(b[5])
	z0 -= dword(a[6]) * dword(b[6])
	z0 -= dword(a[5]) * dword(b[7])
	z0 += z2

	c[4] = word(z0) & radixMask
	c[12] = word(z1) & radixMask

	z0 >>= 28
	z1 >>= 28

	//j = 5
	z2 = 0
	z2 += dword(a[5]) * dword(b[0])
	z2 += dword(a[4]) * dword(b[1])
	z2 += dword(a[3]) * dword(b[2])
	z2 += dword(a[2]) * dword(b[3])
	z2 += dword(a[1]) * dword(b[4])
	z2 += dword(a[0]) * dword(b[5])

	z1 += aa5 * bb0
	z1 += aa4 * bb1
	z1 += aa3 * bb2
	z1 += aa2 * bb3
	z1 += aa1 * bb4
	z1 += aa0 * bb5
	z1 -= z2

	z0 += dword(a[13]) * dword(b[8])
	z0 += dword(a[12]) * dword(b[9])
	z0 += dword(a[11]) * dword(b[10])
	z0 += dword(a[10]) * dword(b[11])
	z0 += dword(a[9]) * dword(b[12])
	z0 += dword(a[8]) * dword(b[13])
	z0 += z2

	z2 = 0
	z2 += aa7 * bb6
	z2 += aa6 * bb7

	z1 += dword(a[15]) * dword(b[14])
	z1 += dword(a[14]) * dword(b[15])
	z1 += z2

	z0 -= dword(a[7]) * dword(b[6])
	z0 -= dword(a[6]) * dword(b[7])
	z0 += z2

	c[5] = word(z0) & radixMask
	c[13] = word(z1) & radixMask

	z0 >>= 28
	z1 >>= 28

	//j = 6
	z2 = 0
	z2 += dword(a[6]) * dword(b[0])
	z2 += dword(a[5]) * dword(b[1])
	z2 += dword(a[4]) * dword(b[2])
	z2 += dword(a[3]) * dword(b[3])
	z2 += dword(a[2]) * dword(b[4])
	z2 += dword(a[1]) * dword(b[5])
	z2 += dword(a[0]) * dword(b[6])

	z1 += aa6 * bb0
	z1 += aa5 * bb1
	z1 += aa4 * bb2
	z1 += aa3 * bb3
	z1 += aa2 * bb4
	z1 += aa1 * bb5
	z1 += aa0 * bb6
	z1 -= z2

	z0 += dword(a[14]) * dword(b[8])
	z0 += dword(a[13]) * dword(b[9])
	z0 += dword(a[12]) * dword(b[10])
	z0 += dword(a[11]) * dword(b[11])
	z0 += dword(a[10]) * dword(b[12])
	z0 += dword(a[9]) * dword(b[13])
	z0 += dword(a[8]) * dword(b[14])
	z0 += z2

	z2 = 0
	z2 += aa7 * bb7
	z1 += dword(a[15]) * dword(b[15])
	z1 += z2
	z0 -= dword(a[7]) * dword(b[7])
	z0 += z2

	c[6] = word(z0) & radixMask
	c[14] = word(z1) & radixMask

	z0 >>= 28
	z1 >>= 28

	//j = 7
	z2 = 0
	z2 += dword(a[7]) * dword(b[0])
	z2 += dword(a[6]) * dword(b[1])
	z2 += dword(a[5]) * dword(b[2])
	z2 += dword(a[4]) * dword(b[3])
	z2 += dword(a[3]) * dword(b[4])
	z2 += dword(a[2]) * dword(b[5])
	z2 += dword(a[1]) * dword(b[6])
	z2 += dword(a[0]) * dword(b[7])

	z1 += aa7 * bb0
	z1 += aa6 * bb1
	z1 += aa5 * bb2
	z1 += aa4 * bb3
	z1 += aa3 * bb4
	z1 += aa2 * bb5
	z1 += aa1 * bb6
	z1 += aa0 * bb7
	z1 -= z2

	z0 += dword(a[15]) * dword(b[8])
	z0 += dword(a[14]) * dword(b[9])
	z0 += dword(a[13]) * dword(b[10])
	z0 += dword(a[12]) * dword(b[11])
	z0 += dword(a[11]) * dword(b[12])
	z0 += dword(a[10]) * dword(b[13])
	z0 += dword(a[9]) * dword(b[14])
	z0 += dword(a[8]) * dword(b[15])
	z0 += z2

	z2 = 0
	z1 += z2
	z0 += z2

	c[7] = word(z0) & radixMask
	c[15] = word(z1) & radixMask

	z0 >>= 28
	z1 >>= 28

	// finish

	z0 += z1
	z0 += dword(c[8])
	z1 += dword(c[0])

	c[8] = word(z0) & radixMask
	c[0] = word(z1) & radixMask

	z0 >>= 28
	z1 >>= 28

	c[9] += word(z0)
	c[1] += word(z1)

	return c
}
