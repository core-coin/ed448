package ed448

import (
	. "gopkg.in/check.v1"
)

func (s *Ed448Suite) Test_PointDouble(c *C) {
	q := &twExtendedPoint{
		&bigNumber{0x08354b7a, 0x0895b3e8,
			0x06ae5175, 0x0644b394,
			0x0b7faf9e, 0x0c5237db,
			0x013a0c90, 0x08f5bce0,
			0x09a3d79b, 0x00f17559,
			0x0de8f041, 0x073e222f,
			0x0dc2b7ee, 0x005ac354,
			0x0766db38, 0x065631fe,
		},
		&bigNumber{0x00398885, 0x055c9bed,
			0x0ae443ca, 0x0fd70ea4,
			0x09e2a7d2, 0x04ac2e9d,
			0x00678287, 0x0294768e,
			0x0b604cea, 0x07b49317,
			0x0dc2a6d9, 0x0e44a6fb,
			0x09db3965, 0x049d3bf5,
			0x03e655fe, 0x003a9c02,
		},
		&bigNumber{0x0fd57162, 0x0a39f768,
			0x03009756, 0x065d735f,
			0x0d1da282, 0x0589ecd7,
			0x003196b1, 0x0c001dfe,
			0x019f1050, 0x0152e8d2,
			0x0c14ff38, 0x00f7a446,
			0x028053f6, 0x0f8a91e9,
			0x05a8d694, 0x09d5ae86,
		},
		&bigNumber{0x04198f2e, 0x0d82440f,
			0x0fce100e, 0x0af4829d,
			0x0d5c3516, 0x0094a0da,
			0x078cdb39, 0x0e738836,
			0x01ec536d, 0x06dfd1e9,
			0x0ee16173, 0x0addc8c0,
			0x0797fb1d, 0x059741a3,
			0x0a7f9c34, 0x088fe0a6,
		},
	}

	p := &twExtendedPoint{
		&bigNumber{0}, &bigNumber{0},
		&bigNumber{0}, &bigNumber{0},
	}

	p.double(q, false)

	expected := &twExtendedPoint{
		&bigNumber{0x00d8f04c, 0x03e54689,
			0x0eb4db2b, 0x0887ba34,
			0x0a5b4ebc, 0x0f6c0261,
			0x03bfa803, 0x0408ff02,
			0x03b4ef26, 0x0465c028,
			0x0cd47378, 0x064c55b4,
			0x08245850, 0x01912682,
			0x0dcbf92c, 0x07a7fa30,
		},
		&bigNumber{0x0d94d1a6, 0x0f7306e8,
			0x0278b336, 0x04362b7b,
			0x0faf02b9, 0x06b01d18,
			0x07a597da, 0x0bd6add0,
			0x047afa98, 0x0e64e897,
			0x0bbf88e6, 0x01d0a534,
			0x04a52b9d, 0x0af374e0,
			0x05091d54, 0x00fcf1a5,
		},
		&bigNumber{0x042318ce, 0x04aecdae,
			0x0e8f196b, 0x0019d2e3,
			0x045d147c, 0x060b153e,
			0x0adf2c37, 0x0419cdd8,
			0x06d19046, 0x00d18821,
			0x06c7b9c2, 0x0c0ffd68,
			0x0b7e4ca2, 0x06da0d56,
			0x0952b40f, 0x03008395,
		},
		&bigNumber{0x04643593, 0x000e0fdd,
			0x013f29f3, 0x0bb8992d,
			0x0a30d344, 0x09151eec,
			0x0d12bb82, 0x05c7a054,
			0x0103c2c6, 0x08a61fe2,
			0x0aced4bf, 0x0f76d481,
			0x0db774be, 0x065ef8a8,
			0x0ff47a71, 0x0f49f73e,
		}}

	c.Assert(p, DeepEquals, expected)

	resetPoint(p)

	w := &twExtendedPoint{
		&bigNumber{1},
		&bigNumber{2},
		&bigNumber{3},
		&bigNumber{4},
	}

	p.double(w, true)

	expected2 := &twExtendedPoint{
		&bigNumber{0x0000003b, 0x10000000,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0ffffffe, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
		},
		&bigNumber{0x0000000e, 0x00000000,
			0x00000000, 0x00000000,
			0x00000000, 0x00000000,
			0x00000000, 0x00000000,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
		},
		&bigNumber{0x0000002c, 0x10000000,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0ffffffe, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
		},
		&bigNumber{0x00000002, 0x10000000,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0ffffffe, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
		}}

	c.Assert(p, DeepEquals, expected2)
}

func resetPoint(p *twExtendedPoint) {
	p = &twExtendedPoint{
		&bigNumber{0},
		&bigNumber{0},
		&bigNumber{0},
		&bigNumber{0},
	}
}

func (s *Ed448Suite) Test_AddNielsToExtended_BeforeDouble(c *C) {
	extdPoint := &twExtendedPoint{
		&bigNumber{},
		&bigNumber{1},
		&bigNumber{1},
		&bigNumber{},
	}
	n := &twNiels{
		&bigNumber{0x068d5b74},
		&bigNumber{0x068d5b74},
		&bigNumber{0x068d5b74},
	}

	expected := &twExtendedPoint{
		&bigNumber{0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0ffffffe, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
		},
		&bigNumber{0x0d1ab6e7, 0x00000000,
			0x00000000, 0x00000000,
			0x00000000, 0x00000000,
			0x00000000, 0x00000000,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
		},
		&bigNumber{0x00000000, 0x00000000,
			0x00000000, 0x00000000,
			0x00000000, 0x00000000,
			0x00000000, 0x00000000,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
		}, &bigNumber{},
	}

	extdPoint.addNielsToExtended(n, true)

	c.Assert(extdPoint.x, DeepEquals, expected.x)
	c.Assert(extdPoint.y, DeepEquals, expected.y)
	c.Assert(extdPoint.z, DeepEquals, expected.z)
	c.Assert(extdPoint.t, DeepEquals, expected.t)
}

func (s *Ed448Suite) Test_AddNielsToProjective(c *C) {
	n := &twNiels{&bigNumber{0x08fcb20f, 0x04611087,
		0x01cc6f32, 0x0df43db2,
		0x04516644, 0x0ffdde9f,
		0x091686b9, 0x05199177,
		0x0fd34473, 0x0b72b441,
		0x0cb1c72b, 0x08d45684,
		0x00fc17a5, 0x01518137,
		0x007f74d3, 0x0a456d13},
		&bigNumber{0x09b607dc, 0x01430f14,
			0x016715fc, 0x0e992ccd,
			0x00a32a09, 0x0a62209b,
			0x0c26b8e4, 0x0b889ced,
			0x0ac109cf, 0x059bf9a3,
			0x0b7feac2, 0x06871bb3,
			0x0d9a0e6b, 0x0f4a4d5f,
			0x00cd69a5, 0x0b95db46},
		&bigNumber{0x08bda702, 0x03630441,
			0x01561558, 0x07bc5686,
			0x0e30416f, 0x0f344bc8,
			0x080f59d7, 0x0a645370,
			0x07d00ace, 0x0b4c2007,
			0x0b26f8cc, 0x0ee79620,
			0x00b5403d, 0x0a6a558e,
			0x066f3d19, 0x08f1d2c7},
	}

	extdPoint := twExtendedPoint{
		&bigNumber{0x00d8f04c, 0x03e54689,
			0x0eb4db2b, 0x0887ba34,
			0x0a5b4ebc, 0x0f6c0261,
			0x03bfa803, 0x0408ff02,
			0x03b4ef26, 0x0465c028,
			0x0cd47378, 0x064c55b4,
			0x08245850, 0x01912682,
			0x0dcbf92c, 0x07a7fa30,
		},
		&bigNumber{0x0d94d1a6, 0x0f7306e8,
			0x0278b336, 0x04362b7b,
			0x0faf02b9, 0x06b01d18,
			0x07a597da, 0x0bd6add0,
			0x047afa98, 0x0e64e897,
			0x0bbf88e6, 0x01d0a534,
			0x04a52b9d, 0x0af374e0,
			0x05091d54, 0x00fcf1a5,
		},
		&bigNumber{0x042318ce, 0x04aecdae,
			0x0e8f196b, 0x0019d2e3,
			0x045d147c, 0x060b153e,
			0x0adf2c37, 0x0419cdd8,
			0x06d19046, 0x00d18821,
			0x06c7b9c2, 0x0c0ffd68,
			0x0b7e4ca2, 0x06da0d56,
			0x0952b40f, 0x03008395,
		},
		&bigNumber{0x04643593, 0x000e0fdd,
			0x013f29f3, 0x0bb8992d,
			0x0a30d344, 0x09151eec,
			0x0d12bb82, 0x05c7a054,
			0x0103c2c6, 0x08a61fe2,
			0x0aced4bf, 0x0f76d481,
			0x0db774be, 0x065ef8a8,
			0x0ff47a71, 0x0f49f73e,
		},
	}
	expected := &twExtendedPoint{
		&bigNumber{0x0662c9a5, 0x0e2bc383,
			0x09b2fc38, 0x0042d545,
			0x0431bbe8, 0x09e2a364,
			0x03b8e92e, 0x0df6d043,
			0x07136f20, 0x00bde4fe,
			0x0ca79859, 0x0c484320,
			0x099507c4, 0x0ef683e6,
			0x09f8221d, 0x0b1fdcb8,
		},
		&bigNumber{0x0aaf871f, 0x08fcadaf,
			0x0974aaea, 0x07d73c92,
			0x0bdaba0c, 0x069d1bf6,
			0x0906e75c, 0x0020e493,
			0x07a2e1ec, 0x06e27878,
			0x00e9c9d2, 0x08e429f5,
			0x026f7c86, 0x0420e6c5,
			0x0304fccb, 0x0599fe0e,
		},
		&bigNumber{0x01b26129, 0x071c89cf,
			0x0b012391, 0x0074b87c,
			0x0331b5fb, 0x0a2cbc8d,
			0x0d1a4729, 0x0ab451d3,
			0x0308cad6, 0x0e086c2b,
			0x03bd396c, 0x0cd2bd87,
			0x0910f41c, 0x090be75a,
			0x0a8d7a0e, 0x07ec7ea8,
		},
		&bigNumber{0x08b7d023, 0x05bc6276,
			0x03e2082d, 0x09d3eba3,
			0x0ecc2af3, 0x07a4c7be,
			0x08ca49b8, 0x0ebe1040,
			0x0cf6ddeb, 0x015ec1ff,
			0x010eed61, 0x0882e84d,
			0x07fefb78, 0x0d97e204,
			0x02e940a1, 0x0537d7c0,
		},
	}

	extdPoint.addNielsToExtended(n, false)

	c.Assert(extdPoint.x, DeepEquals, expected.x)
	c.Assert(extdPoint.y, DeepEquals, expected.y)
	c.Assert(extdPoint.z, DeepEquals, expected.z)
	c.Assert(extdPoint.t, DeepEquals, expected.t)
}

func (s *Ed448Suite) Test_ConvertNielsToExtended(c *C) {
	p := &twExtendedPoint{
		&bigNumber{},
		&bigNumber{0x01},
		&bigNumber{0x01},
		&bigNumber{},
	}
	niels := &twNiels{
		&bigNumber{0x068d5b74},
		&bigNumber{0x068d5b74},
		&bigNumber{0x068d5b74},
	}

	expected := &twExtendedPoint{
		&bigNumber{0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0ffffffe, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
		},
		&bigNumber{0x0d1ab6e8},
		&bigNumber{0x00000001},
		&bigNumber{0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0ffffffe, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
		},
	}

	p.nielsToExtended(niels)

	c.Assert(p.x, DeepEquals, expected.x)
	c.Assert(p.y, DeepEquals, expected.y)
	c.Assert(p.z, DeepEquals, expected.z)
	c.Assert(p.t, DeepEquals, expected.t)
}

func (s *Ed448Suite) Test_PrecomputedScalarMultiplication(c *C) {
	scalar := [scalarWords]uint32{0}

	p := curve.precomputedScalarMul(scalar)

	expP := &twExtendedPoint{
		&bigNumber{0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0ffffffe, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
		},
		&bigNumber{0x0b1ff82e, 0x05e98b74,
			0x000cecf1, 0x0277711a,
			0x0f9b17c5, 0x0c98aadc,
			0x05b06211, 0x0bc17782,
			0x0809fef2, 0x08bb648f,
			0x0323239f, 0x0d37d81d,
			0x0389402c, 0x0cbabc81,
			0x087aaae9, 0x01b50b05,
		},
		&bigNumber{0x04e007d1, 0x0a16748b,
			0x0ff3130e, 0x0d888ee5,
			0x0064e83a, 0x03675523,
			0x0a4f9dee, 0x043e887d,
			0x07f6010c, 0x07449b70,
			0x0cdcdc60, 0x02c827e2,
			0x0c76bfd3, 0x0345437e,
			0x07855516, 0x0e4af4fa,
		},
		&bigNumber{0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0ffffffe, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
			0x0fffffff, 0x0fffffff,
		},
	}

	c.Assert(p.x, DeepEquals, expP.x)
	c.Assert(p.y, DeepEquals, expP.y)
	c.Assert(p.z, DeepEquals, expP.z)
	c.Assert(p.t, DeepEquals, expP.t)
}
