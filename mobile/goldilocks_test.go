package mobile

import (
	"fmt"
	"testing"
)

func TestEd448HDWalletsGenerateKey(t *testing.T) {
	tests := []struct {
		seed  string
		index string
		key   string
	}{
		{
			"0x37a615be9f9e403a7b539ad9564c037e6ea0827628ecc664d436bbe3a37c3ab93d4f0693ba2b7dbf3634836e016736cf8403d949b516308c8c2a4c49acfbaba7",
			"0",
			"0xc06b81ed5e7be6a8604a863c1b7a6bc6b35256535ffcf23f35cc1531621cde892d45b21bfd647a79ba06b145dbd45f4200ff54fa787533bf94",
		},
		{
			"0x4db501dc0bdb8770bec9a2a3fb54c73b66e2abc1bd0d1b71dbf7beb339f65ef148ab9eb901241e8ba02eb570a7406e4be429b0a98aaa5729cae9bef895ec0b6b",
			"1",
			"0xa3b210b8771782a74d877a26c7f86aec9a6c9177972fd1f4b5d1a79524a7d48b15b1a3eb9fd2feefd18c8b4ca24a66f478c37e472037f3a8e5",
		},
		{
			"cde1fdb6597e7103ec622b76381a6f6a4847c00f5f3c7190e1ea87aae3ba512db23d08a614dcc6448ef85d1d5303861258c48902059bcf33bf40a61546b2079c",
			"5",
			"0xe6159b2a38dbbe289b2000354035bc864b3d53b7af9a5967449c167eb4144b6efafabd2f66f93d445d2fb49b515c6509ceb9d50b99dd8084ef",
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprint("test", i), func(t *testing.T) {
			key, err := Ed448HDWalletsGenerateKey(test.seed, test.index)
			if err != nil {
				t.Fatal("returned error:", err)
			}
			if key != test.key {
				t.Fatalf("returned key is %s but expected key is %s", key, test.key)
			}
		})
	}
}

func TestEd448GenerateKey(t *testing.T) {
	tests := []struct {
		seed string
		key  string
	}{
		{
			"0x37a615be9f9e403a7b539ad9564c037e6ea0827628ecc664d436bbe3a37c3ab93d4f0693ba2b7dbf3634836e016736cf8403d949b516308c8c2a4c49acfbaba7",
			"0x37a615be9f9e403a7b539ad9564c037e6ea0827628ecc664d436bbe3a37c3ab93d4f0693ba2b7dbf3634836e016736cf8403d949b516308c0c",
		},
		{
			"0x4db501dc0bdb8770bec9a2a3fb54c73b66e2abc1bd0d1b71dbf7beb339f65ef148ab9eb901241e8ba02eb570a7406e4be429b0a98aaa5729cae9bef895ec0b6b",
			"0x4db501dc0bdb8770bec9a2a3fb54c73b66e2abc1bd0d1b71dbf7beb339f65ef148ab9eb901241e8ba02eb570a7406e4be429b0a98aaa57294a",
		},
		{
			"cde1fdb6597e7103ec622b76381a6f6a4847c00f5f3c7190e1ea87aae3ba512db23d08a614dcc6448ef85d1d5303861258c48902059bcf33bf40a61546b2079c",
			"0xcde1fdb6597e7103ec622b76381a6f6a4847c00f5f3c7190e1ea87aae3ba512db23d08a614dcc6448ef85d1d5303861258c48902059bcf333f",
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprint("test", i), func(t *testing.T) {
			key, err := Ed448GenerateKey(test.seed)
			if err != nil {
				t.Fatal("returned error:", err)
			}
			if key != test.key {
				t.Fatalf("returned key is %s but expected key is %s", key, test.key)
			}
		})
	}
}

func TestEd448DerivePublicKey(t *testing.T) {
	tests := []struct {
		private string
		public  string
	}{
		{
			"0x37a615be9f9e403a7b539ad9564c037e6ea0827628ecc664d436bbe3a37c3ab93d4f0693ba2b7dbf3634836e016736cf8403d949b516308c0c",
			"0xdc752d354b44f2aef2e18056aaa9d8c58445972eccc6f9d2475713db3c5bd622cc8e80735f596afd41ad5d987886fd40ad2681be95dd438d00",
		},
		{
			"0x4db501dc0bdb8770bec9a2a3fb54c73b66e2abc1bd0d1b71dbf7beb339f65ef148ab9eb901241e8ba02eb570a7406e4be429b0a98aaa57294a",
			"0x3b470fe5b42f7cdf4a534679c824ad1088d46daa2c5ba88925b259913fb301591073ab0f085c4b3d46334cf159578832a9bc0728dd592d4380",
		},
		{
			"0xcde1fdb6597e7103ec622b76381a6f6a4847c00f5f3c7190e1ea87aae3ba512db23d08a614dcc6448ef85d1d5303861258c48902059bcf333f",
			"0x328f102a67ea72ad65b7e6588fbc04f3be501e2c4146bef7d14ecc485f7a5e52703cc4f085e9b3209112f096f86e070003608698fbaa8ef700",
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprint("test", i), func(t *testing.T) {
			public, err := Ed448DerivePublicKey(test.private)
			if err != nil {
				t.Fatal("returned error:", err)
			}
			if public != test.public {
				t.Fatalf("returned public is %s but expected public is %s", public, test.public)
			}
		})
	}
}

func TestEd448Sign(t *testing.T) {
	tests := []struct {
		private   string
		message   string
		signature string
	}{
		{
			"0x37a615be9f9e403a7b539ad9564c037e6ea0827628ecc664d436bbe3a37c3ab93d4f0693ba2b7dbf3634836e016736cf8403d949b516308c0c",
			"0x7f8b6b088b6d74c2852fc86c796dca07b44eed6fb3daf5e6b59f7c364db14528",
			"0x8e6248c90a9b23fdbfaf57575cbabd45d10d8d362a04d59a3a47da9ddf97fe48c2d51911e7f33beacea00f58be4fada838f13193ae61ce08000c388cfc26bad73c7b71f5c26c67839e49b301ec4f7936d121a5968dc20d334006ee5e305ce30464809c05bd80053348b40b805a725ee72600",
		},
		{
			"0x4db501dc0bdb8770bec9a2a3fb54c73b66e2abc1bd0d1b71dbf7beb339f65ef148ab9eb901241e8ba02eb570a7406e4be429b0a98aaa57294a",
			"0x7880aec93413f117ef14bd4e6d130875ab2c7d7d55a064fac3c2f7bd51516380",
			"0xbfcb86fd1cb275c976633bf7ad1cabd88d453b782bcda4ea20280d895e82182a41f367b33cba19f69692055e4c3eb2cebd7818c4de233ad4004cb6e5dad9f90ac9be9ff31cbcc4c22e744ac82d472dbd8b14a9b1722e51b63229b40761fd4abb224ab691646e0458d29dd3bfcc03c0842100",
		},
		{
			"0xcde1fdb6597e7103ec622b76381a6f6a4847c00f5f3c7190e1ea87aae3ba512db23d08a614dcc6448ef85d1d5303861258c48902059bcf333f",
			"0x3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb",
			"0x2bd24f303b3b31a8e2c55de7b98455ecd4193354c1e98bbe7e5530dfc4faac4a95578ad16e6aee741a46665ea763474d2437299cf9841a548000413c4720c6137ba8585e43d34db3772b44f90ddf9d3dab6f575c667f27e5632d3755916a4a6873fc4fa338f54d9b4a3b673b1d33aca23600",
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprint("test", i), func(t *testing.T) {
			signature, err := Ed448Sign(test.private, test.message)
			if err != nil {
				t.Fatal("returned error:", err)
			}
			if signature != test.signature {
				t.Fatalf("returned signature is %s but expected signature is %s", signature, test.signature)
			}
		})
	}
}

func TestEd448Verify(t *testing.T) {
	tests := []struct {
		public    string
		signature string
		message   string
		result    string
	}{
		{
			"0xdc752d354b44f2aef2e18056aaa9d8c58445972eccc6f9d2475713db3c5bd622cc8e80735f596afd41ad5d987886fd40ad2681be95dd438d00",
			"0x8e6248c90a9b23fdbfaf57575cbabd45d10d8d362a04d59a3a47da9ddf97fe48c2d51911e7f33beacea00f58be4fada838f13193ae61ce08000c388cfc26bad73c7b71f5c26c67839e49b301ec4f7936d121a5968dc20d334006ee5e305ce30464809c05bd80053348b40b805a725ee72600",
			"0x7f8b6b088b6d74c2852fc86c796dca07b44eed6fb3daf5e6b59f7c364db14528",
			"true",
		},
		{
			"0x3b470fe5b42f7cdf4a534679c824ad1088d46daa2c5ba88925b259913fb301591073ab0f085c4b3d46334cf159578832a9bc0728dd592d4380",
			"0xbfcb86fd1cb275c976633bf7ad1cabd88d453b782bcda4ea20280d895e82182a41f367b33cba19f69692055e4c3eb2cebd7818c4de233ad4004cb6e5dad9f90ac9be9ff31cbcc4c22e744ac82d472dbd8b14a9b1722e51b63229b40761fd4abb224ab691646e0458d29dd3bfcc03c0842100",
			"0x7880aec93413f117ef14bd4e6d130875ab2c7d7d55a064fac3c2f7bd51516380",
			"true",
		},
		{
			"0x328f102a67ea72ad65b7e6588fbc04f3be501e2c4146bef7d14ecc485f7a5e52703cc4f085e9b3209112f096f86e070003608698fbaa8ef700",
			"0x2bd24f303b3b31a8e2c55de7b98455ecd4193354c1e98bbe7e5530dfc4faac4a95578ad16e6aee741a46665ea763474d2437299cf9841a548000413c4720c6137ba8585e43d34db3772b44f90ddf9d3dab6f575c667f27e5632d3755916a4a6873fc4fa338f54d9b4a3b673b1d33aca23600",
			"0x3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb",
			"true",
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprint("test", i), func(t *testing.T) {
			result, err := Ed448Verify(test.public, test.signature, test.message)
			if err != nil {
				t.Fatal("returned error:", err)
			}
			if result != test.result {
				t.Fatalf("returned result is %s but expected result is %s", result, test.result)
			}
		})
	}
}
