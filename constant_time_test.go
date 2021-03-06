package ed448

import . "gopkg.in/check.v1"

func (s *Ed448Suite) Test_ConstantTimeMask(c *C) {
	a := new(bigNumber)
	b := mustDeserialize(serialized{
		0x9f, 0x93, 0xed, 0x0a, 0x84, 0xde, 0xf0,
		0xc7, 0xa0, 0x4b, 0x3f, 0x03, 0x70, 0xc1,
		0x96, 0x3d, 0xc6, 0x94, 0x2d, 0x93, 0xf3,
		0xaa, 0x7e, 0x14, 0x96, 0xfa, 0xec, 0x9c,
		0x70, 0xd0, 0x59, 0x3c, 0x5c, 0x06, 0x5f,
		0x24, 0x33, 0xf7, 0xad, 0x26, 0x6a, 0x3a,
		0x45, 0x98, 0x60, 0xf4, 0xaf, 0x4f, 0x1b,
		0xff, 0x92, 0x26, 0xea, 0xa0, 0x7e, 0x29,
	})
	m := word(lmask)
	exp, _ := deserialize(serialized{
		0x9f, 0x93, 0xed, 0x0a, 0x84, 0xde, 0xf0,
		0xc7, 0xa0, 0x4b, 0x3f, 0x03, 0x70, 0xc1,
		0x96, 0x3d, 0xc6, 0x94, 0x2d, 0x93, 0xf3,
		0xaa, 0x7e, 0x14, 0x96, 0xfa, 0xec, 0x9c,
		0x70, 0xd0, 0x59, 0x3c, 0x5c, 0x06, 0x5f,
		0x24, 0x33, 0xf7, 0xad, 0x26, 0x6a, 0x3a,
		0x45, 0x98, 0x60, 0xf4, 0xaf, 0x4f, 0x1b,
		0xff, 0x92, 0x26, 0xea, 0xa0, 0x7e, 0x29,
	})
	mask(a, b, m)

	c.Assert(a, DeepEquals, exp)

	m = word(0x00000000)
	exp, _ = deserialize(serialized{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})
	mask(a, b, m)

	c.Assert(a, DeepEquals, exp)

	m = word(0x00000001)
	exp, _ = deserialize(serialized{
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})
	mask(a, b, m)

	c.Assert(a, DeepEquals, exp)
}

func (s *Ed448Suite) Test_constantTimeSelectBigNumber(c *C) {
	l := mustDeserialize(serialized{
		0x9f, 0x93, 0xed, 0x0a, 0x84, 0xde, 0xf0,
		0xc7, 0xa0, 0x4b, 0x3f, 0x03, 0x70, 0xc1,
		0x96, 0x3d, 0xc6, 0x94, 0x2d, 0x93, 0xf3,
		0xaa, 0x7e, 0x14, 0x96, 0xfa, 0xec, 0x9c,
		0x70, 0xd0, 0x59, 0x3c, 0x5c, 0x06, 0x5f,
		0x24, 0x33, 0xf7, 0xad, 0x26, 0x6a, 0x3a,
		0x45, 0x98, 0x60, 0xf4, 0xaf, 0x4f, 0x1b,
		0xff, 0x92, 0x26, 0xea, 0xa0, 0x7e, 0x29,
	})
	r := mustDeserialize(serialized{
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})

	ret := constantTimeSelectBigNumber(l, r, decafFalse)
	c.Assert(ret, DeepEquals, l)

	ret = constantTimeSelectBigNumber(l, r, decafTrue)
	c.Assert(ret, DeepEquals, r)
}

func (s *Ed448Suite) Test_constantTimeSelectPoint(c *C) {
	l := NewPointFromBytes([]byte{
		0x5d, 0xf1, 0x18, 0xbf, 0x8e, 0x3f, 0xfe, 0xcd,
		0x95, 0xd3, 0x49, 0xda, 0xcd, 0xac, 0x2c, 0xdf,
		0x72, 0x5e, 0xb7, 0x61, 0x44, 0xf1, 0x93, 0xa6,
		0x70, 0x8e, 0x64, 0xff, 0x7c, 0xec, 0x6c, 0xe5,
		0xc6, 0x8d, 0x8f, 0xa0, 0x43, 0x23, 0x45, 0x33,
		0x73, 0x71, 0xe6, 0x2f, 0x57, 0xbb, 0x0f, 0x70,
		0x11, 0x8c, 0x62, 0x26, 0x9e, 0x17, 0x5d, 0x22,
	})

	r := NewPointFromBytes([]byte{
		0x1d, 0xf1, 0x18, 0xbf, 0x8e, 0x3f, 0xfe, 0xcd,
		0x25, 0xd3, 0x49, 0xda, 0xcd, 0xac, 0x2c, 0xdf,
		0x32, 0x5e, 0xb7, 0x61, 0x44, 0xf1, 0x93, 0xa6,
		0x40, 0x8e, 0x64, 0xff, 0x7c, 0xec, 0x6c, 0xe5,
		0x56, 0x8d, 0x8f, 0xa0, 0x43, 0x23, 0x45, 0x33,
		0x63, 0x71, 0xe6, 0x2f, 0x57, 0xbb, 0x0f, 0x70,
		0x71, 0x8c, 0x62, 0x26, 0x9e, 0x17, 0x5d, 0x22,
	})

	ret := ConstantTimeSelectPoint(l, r, uint32(decafFalse))
	c.Assert(ret, DeepEquals, l)

	ret = ConstantTimeSelectPoint(l, r, uint32(decafTrue))
	c.Assert(ret, DeepEquals, r)
}

func (s *Ed448Suite) Test_constantTimeSelectScalar(c *C) {
	l := NewScalar([]byte{
		0x5d, 0xf1, 0x18, 0xbf, 0x8e, 0x3f, 0xfe, 0xcd,
		0x95, 0xd3, 0x49, 0xda, 0xcd, 0xac, 0x2c, 0xdf,
		0x72, 0x5e, 0xb7, 0x61, 0x44, 0xf1, 0x93, 0xa6,
		0x70, 0x8e, 0x64, 0xff, 0x7c, 0xec, 0x6c, 0xe5,
		0xc6, 0x8d, 0x8f, 0xa0, 0x43, 0x23, 0x45, 0x33,
		0x73, 0x71, 0xe6, 0x2f, 0x57, 0xbb, 0x0f, 0x70,
		0x11, 0x8c, 0x62, 0x26, 0x9e, 0x17, 0x5d, 0x22,
	})

	r := NewScalar([]byte{
		0x1d, 0xf1, 0x18, 0xbf, 0x8e, 0x3f, 0xfe, 0xcd,
		0x25, 0xd3, 0x49, 0xda, 0xcd, 0xac, 0x2c, 0xdf,
		0x32, 0x5e, 0xb7, 0x61, 0x44, 0xf1, 0x93, 0xa6,
		0x40, 0x8e, 0x64, 0xff, 0x7c, 0xec, 0x6c, 0xe5,
		0x56, 0x8d, 0x8f, 0xa0, 0x43, 0x23, 0x45, 0x33,
		0x63, 0x71, 0xe6, 0x2f, 0x57, 0xbb, 0x0f, 0x70,
		0x71, 0x8c, 0x62, 0x26, 0x9e, 0x17, 0x5d, 0x22,
	})

	ret := ConstantTimeSelectScalar(l, r, uint32(decafFalse))
	c.Assert(ret, DeepEquals, l)

	ret = ConstantTimeSelectScalar(l, r, uint32(decafTrue))
	c.Assert(ret, DeepEquals, r)
}
