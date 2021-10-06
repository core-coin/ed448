package ed448

// TODO: this has changed
//c = a * a
func karatsubaSquare(c, a *bigNumber) *bigNumber {
	
	var aa0 dword = dword(a[0]) + dword(a[8]) // 0 - 8
	var aa1 dword = dword(a[1]) + dword(a[9]) // 1 - 9
	var aa2 dword = dword(a[2]) + dword(a[10])
	var aa3 dword = dword(a[3]) + dword(a[11])
	var aa4 dword = dword(a[4]) + dword(a[12])
	var aa5 dword = dword(a[5]) + dword(a[13])
	var aa6 dword = dword(a[6]) + dword(a[14])
	var aa7 dword = dword(a[7]) + dword(a[15]) //7 - 15
	

	var z0, z1, z2 dword

	//j = 0
	z2 = 0
	z2 += dword(a[0]) * dword(a[0])
	z1 += aa0 * aa0
	z1 -= z2
	z0 += dword(a[8]) * dword(a[8])
	z0 += z2

	z2 = 0
	z2 += (aa7 * aa1) << 1 // (a7+a15) * (a1+a9)
	z2 += (aa6 * aa2) << 1 // (a6+a14) * (a2+a10)
	z2 += (aa5 * aa3) << 1 // (a5+a13) * (a3+a11)
	z2 += aa4 * aa4

	z1 += (dword(a[15]) * dword(a[9])) << 1
	z1 += (dword(a[14]) * dword(a[10])) << 1
	z1 += (dword(a[13]) * dword(a[11])) << 1
	z1 += dword(a[12]) * dword(a[12])
	z1 += z2

	z0 -= (dword(a[7]) * dword(a[1])) << 1
	z0 -= (dword(a[6]) * dword(a[2])) << 1
	z0 -= (dword(a[5]) * dword(a[3])) << 1
	z0 -= dword(a[4]) * dword(a[4])
	z0 += z2

	c[0] = word(z0) & radixMask
	c[8] = word(z1) & radixMask

	z0 >>= 28
	z1 >>= 28

	//j = 1
	z2 = (dword(a[1]) * dword(a[0])) << 1

	z1 += (aa1 * aa0) << 1
	z1 -= z2

	z0 += (dword(a[9]) * dword(a[8])) << 1
	z0 += z2

	z2 = 0
	z2 += aa7 * aa2
	z2 += aa6 * aa3
	z2 += aa5 * aa4
	z2 <<= 1

	z1 += (dword(a[15]) * dword(a[10])) << 1
	z1 += (dword(a[14]) * dword(a[11])) << 1
	z1 += (dword(a[13]) * dword(a[12])) << 1
	z1 += z2

	z0 -= (dword(a[7]) * dword(a[2])) << 1
	z0 -= (dword(a[6]) * dword(a[3])) << 1
	z0 -= (dword(a[5]) * dword(a[4])) << 1
	z0 += z2

	c[1] = word(z0) & radixMask
	c[9] = word(z1) & radixMask

	z0 >>= 28
	z1 >>= 28

	//j = 2
	z2 = 0
	z2 += (dword(a[2]) * dword(a[0])) << 1
	z2 += dword(a[1]) * dword(a[1])

	z1 += (aa2 * aa0) << 1
	z1 += aa1 * aa1
	z1 -= z2

	z0 += (dword(a[10]) * dword(a[8])) << 1
	z0 += dword(a[9]) * dword(a[9])
	z0 += z2

	z2 = 0
	z2 += aa7 * aa3
	z2 += aa6 * aa4
	z2 <<= 1
	z2 += aa5 * aa5

	z1 += (dword(a[15]) * dword(a[11])) << 1
	z1 += (dword(a[14]) * dword(a[12])) << 1
	z1 += dword(a[13]) * dword(a[13])
	z1 += z2

	z0 -= (dword(a[7]) * dword(a[3])) << 1
	z0 -= (dword(a[6]) * dword(a[4])) << 1
	z0 -= dword(a[5]) * dword(a[5])
	z0 += z2

	c[2] = word(z0) & radixMask
	c[10] = word(z1) & radixMask

	z0 >>= 28
	z1 >>= 28

	//j = 3
	z2 = 0
	z2 += dword(a[3]) * dword(a[0])
	z2 += dword(a[2]) * dword(a[1])
	z2 <<= 1

	z1 += (aa3 * aa0) << 1
	z1 += (aa2 * aa1) << 1
	z1 -= z2

	z0 += (dword(a[11]) * dword(a[8])) << 1
	z0 += (dword(a[10]) * dword(a[9])) << 1
	z0 += z2

	z2 = 0
	z2 += (aa7 * aa4) << 1
	z2 += (aa6 * aa5) << 1

	z0 -= (dword(a[7]) * dword(a[4])) << 1
	z0 -= (dword(a[6]) * dword(a[5])) << 1
	z0 += z2

	z1 += (dword(a[15]) * dword(a[12])) << 1
	z1 += (dword(a[14]) * dword(a[13])) << 1
	z1 += z2

	c[3] = word(z0) & radixMask
	c[11] = word(z1) & radixMask

	z0 >>= 28
	z1 >>= 28

	//j = 4
	z2 = 0
	z2 += (dword(a[4]) * dword(a[0])) << 1
	z2 += (dword(a[3]) * dword(a[1])) << 1
	z2 += dword(a[2]) * dword(a[2])

	z1 += (aa4 * aa0) << 1
	z1 += (aa3 * aa1) << 1
	z1 += aa2 * aa2
	z1 -= z2

	z0 += (dword(a[12]) * dword(a[8])) << 1
	z0 += (dword(a[11]) * dword(a[9])) << 1
	z0 += dword(a[10]) * dword(a[10])
	z0 += z2

	z2 = 0
	z2 += (aa7 * aa5) << 1
	z2 += aa6 * aa6

	z1 += (dword(a[15]) * dword(a[13])) << 1
	z1 += dword(a[14]) * dword(a[14])
	z1 += z2

	z0 -= (dword(a[7]) * dword(a[5])) << 1
	z0 -= dword(a[6]) * dword(a[6])
	z0 += z2

	c[4] = word(z0) & radixMask
	c[12] = word(z1) & radixMask

	z0 >>= 28
	z1 >>= 28

	//j = 5
	z2 = 0
	z2 += (dword(a[5]) * dword(a[0])) << 1
	z2 += (dword(a[4]) * dword(a[1])) << 1
	z2 += (dword(a[3]) * dword(a[2])) << 1

	z1 += (aa5 * aa0) << 1
	z1 += (aa4 * aa1) << 1
	z1 += (aa3 * aa2) << 1
	z1 -= z2

	z0 += (dword(a[13]) * dword(a[8])) << 1
	z0 += (dword(a[12]) * dword(a[9])) << 1
	z0 += (dword(a[11]) * dword(a[10])) << 1
	z0 += z2

	z2 = 0
	z2 += (aa7 * aa6) << 1

	z1 += (dword(a[15]) * dword(a[14])) << 1
	z1 += z2

	z0 -= (dword(a[7]) * dword(a[6])) << 1
	z0 += z2

	c[5] = word(z0) & radixMask
	c[13] = word(z1) & radixMask

	z0 >>= 28
	z1 >>= 28

	//j = 6
	z2 = 0
	z2 += (dword(a[6]) * dword(a[0])) << 1
	z2 += (dword(a[5]) * dword(a[1])) << 1
	z2 += (dword(a[4]) * dword(a[2])) << 1
	z2 += dword(a[3]) * dword(a[3])

	z1 += (aa6 * aa0) << 1
	z1 += (aa5 * aa1) << 1
	z1 += (aa4 * aa2) << 1
	z1 += aa3 * aa3
	z1 -= z2

	z0 += (dword(a[14]) * dword(a[8])) << 1
	z0 += (dword(a[13]) * dword(a[9])) << 1
	z0 += (dword(a[12]) * dword(a[10])) << 1
	z0 += dword(a[11]) * dword(a[11])
	z0 += z2

	z2 = 0
	z2 += aa7 * aa7
	z1 += dword(a[15]) * dword(a[15])
	z1 += z2
	z0 -= dword(a[7]) * dword(a[7])
	z0 += z2

	c[6] = word(z0) & radixMask
	c[14] = word(z1) & radixMask

	z0 >>= 28
	z1 >>= 28

	//j = 7
	z2 = 0
	z2 += (dword(a[7]) * dword(a[0])) << 1
	z2 += (dword(a[6]) * dword(a[1])) << 1
	z2 += (dword(a[5]) * dword(a[2])) << 1
	z2 += (dword(a[4]) * dword(a[3])) << 1

	z1 += (aa7 * aa0) << 1
	z1 += (aa6 * aa1) << 1
	z1 += (aa5 * aa2) << 1
	z1 += (aa4 * aa3) << 1
	z1 -= z2

	z0 += (dword(a[15]) * dword(a[8])) << 1
	z0 += (dword(a[14]) * dword(a[9])) << 1
	z0 += (dword(a[13]) * dword(a[10])) << 1
	z0 += (dword(a[12]) * dword(a[11])) << 1
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
