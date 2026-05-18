package ed448

import (
	"bytes"
	crand "crypto/rand"
	"encoding/hex"
	"testing"
)

func TestEdPublicKeyToX448(t *testing.T) {

	p1, _ := hex.DecodeString("b93a28627cfa29fedb03c21aac0faa1ea0ba84c10cefa07c938f2e0adbf996f02c8d00e39695dfb6a0636c8bcb21645b06a869dfbbb489ef00")
	var public PublicKey
	copy(public[:], p1[:])

	p2, _ := hex.DecodeString("163af30230e62cbf36fd8f4713f2204d78fa8f94f79adfe4f49ed1075d12b3a725a5e5c0564faa6445900b4d166b89b76f2db5c374411129")
	var x448Key [56]byte
	copy(x448Key[:], p2[:])

	generatedKey := EdPublicKeyToX448(public)

	if bytes.Compare(x448Key[:], generatedKey[:]) != 0 {
		t.Errorf("x448 key must be: %x\n But it is: %x", x448Key, generatedKey)
	}

}

func TestEdPrivateKeyToX448(t *testing.T) {

	p1, _ := hex.DecodeString("b93a28627cfa29fedb03c21aac0faa1ea0ba84c10cefa07c938f2e0adbf996f02c8d00e39695dfb6a0636c8bcb21645b06a869dfbbb489ef00")
	var priv PrivateKey
	copy(priv[:], p1[:])

	p2, _ := hex.DecodeString("74a4d56b9ca4bb819778d5b089ef89428bbe768825c83264e97cfba7c0a5f3c33d6ac807e3a568d72a605283f89b8afa52b06323704d9278")
	var x448Key [56]byte
	copy(x448Key[:], p2[:])

	generatedKey := EdPrivateKeyToX448(priv)

	if bytes.Compare(x448Key[:], generatedKey[:]) != 0 {
		t.Errorf("x448 key must be: %x\n But it is: %x", x448Key, generatedKey)
	}
}

func TestEd448DeriveSecret(t *testing.T) {

	priv1, _ := Ed448GenerateKey(crand.Reader)
	priv2, _ := Ed448GenerateKey(crand.Reader)
	public1 := Ed448DerivePublicKey(priv1)
	public2 := Ed448DerivePublicKey(priv2)

	generatedKey1 := Ed448DeriveSecret(public1, priv2)
	generatedKey2 := Ed448DeriveSecret(public2, priv1)

	if bytes.Compare(generatedKey1[:], generatedKey2[:]) != 0 {
		t.Errorf("Secret, generated from %x\nand from %x\nmust be the same, but they are not", priv1, priv2)
	}
}

func TestPrivateToSecret(t *testing.T) {

	p, _ := hex.DecodeString("a8ea212cc24ae0fd029a97b64be540885af0e1b7dc9faf4a591742850c4377f857ae9a8f87df1de98e397a5867dd6f20211ef3f234ae71bc56")
	var privKey PrivateKey
	copy(privKey[:], p[:])

	p, _ = hex.DecodeString("1413821ed67083c855c6db4405dd4fa5fdec39e1c761be1415623c1c202c5cb5176e578830372b7e07eb1ef9cf71b19518815c4da0fd2d3594")
	var secretKey PrivateKey
	copy(secretKey[:], p[:])

	generatedKey := PrivateToSecret(privKey)

	if bytes.Compare(secretKey[:], generatedKey[:]) != 0 {
		t.Errorf("Secret key must be: %x\n But it is: %x", secretKey, generatedKey)
	}

}

func TestSecretToPublic(t *testing.T) {

	p, _ := hex.DecodeString("1413821ed67083c855c6db4405dd4fa5fdec39e1c761be1415623c1c202c5cb5176e578830372b7e07eb1ef9cf71b19518815c4da0fd2d3594")
	var secretKey PrivateKey
	copy(secretKey[:], p[:])

	p, _ = hex.DecodeString("b615e57dd4d15c3ed1323725c0ba8b1d7f6e740d08e0e29c6d3ff564c896c0c3dd28a9bb5065e06725c8f9e3f7c2c6bbad4900b7447ecf9880")
	var public PublicKey
	copy(public[:], p[:])

	generatedKey := SecretToPublic(secretKey)

	if bytes.Compare(public[:], generatedKey[:]) != 0 {
		t.Errorf("Public key must be: %x\n But it is: %x", public, generatedKey)
	}

}

func TestPrivateToPublic(t *testing.T) {

	p, _ := hex.DecodeString("a8ea212cc24ae0fd029a97b64be540885af0e1b7dc9faf4a591742850c4377f857ae9a8f87df1de98e397a5867dd6f20211ef3f234ae71bc56")
	var privKey PrivateKey
	copy(privKey[:], p[:])

	p, _ = hex.DecodeString("b615e57dd4d15c3ed1323725c0ba8b1d7f6e740d08e0e29c6d3ff564c896c0c3dd28a9bb5065e06725c8f9e3f7c2c6bbad4900b7447ecf9880")
	var public PublicKey
	copy(public[:], p[:])

	generatedKey := PrivateToPublic(privKey)

	if bytes.Compare(public[:], generatedKey[:]) != 0 {
		t.Errorf("Public key must be: %x\n But it is: %x", public, generatedKey)
	}

}

func TestRandomKey(t *testing.T) {
	privKey, _ := Ed448GenerateKey(crand.Reader)
	privKey[56] &= 0x7f
	secretKey := PrivateToSecret(privKey)
	public1 := SecretToPublic(secretKey)
	public2 := PrivateToPublic(privKey)

	if bytes.Compare(public1[:], public2[:]) != 0 {
		t.Errorf("Public from secret: %x\nDoesnt matches public from private: %x", public1, public2)
	}

}

func TestEd448DerivePublicKey(t *testing.T) {

	p, _ := hex.DecodeString("582f73eb3d951ef93a8c392c7b113ad85c0f60a744c95c47370d4d593593edc0d745eb24fa2130f51fd5b1e6b2363a5405bf1e074ecbf4382d")
	var privKey PrivateKey
	copy(privKey[:], p[:])

	p, _ = hex.DecodeString("4e6ef3aa2a74ce85c9c75de379c72abbce30601db4f66af1535d00190fa5de83af3831fa32e37c59e14a25788e56140896fb59b494e4fdca80")
	var public PublicKey
	copy(public[:], p[:])

	generatedKey := Ed448DerivePublicKey(privKey)

	if bytes.Compare(public[:], generatedKey[:]) != 0 {
		t.Errorf("Public key must be: %x\n But it is: %x", public, generatedKey)
	}

	p, _ = hex.DecodeString("59fc82f514f3fc8d02d987e52a03cdcae81a257bed6ec9b668bf6acd8fe9e7d27cbcc4d8f463d917642d30e7ca44c3521370f78790b3b561dd")
	copy(privKey[:], p[:])
	p, _ = hex.DecodeString("3cba3b2560c2779170ce5947f55bf73b93a1dd51d99b0b483ed0cfb5a9bb8409830c0f96068c799dbc6a28ca6bc1aad95d0387c36a731d7800")
	copy(public[:], p[:])
	generatedKey = Ed448DerivePublicKey(privKey)

	if bytes.Compare(public[:], generatedKey[:]) != 0 {
		t.Errorf("Public key must be: %x\n But it is: %x", public, generatedKey)
	}

}

func TestSignWithPrivate(t *testing.T) {

	p, _ := hex.DecodeString("64c2754ee8f55f285d1c6efac34345c78da28df5c31d9ae3748417e0754903004eca31389e978df148e3941de8d4c3585b6dd3669903f00bb5")
	var priv PrivateKey
	copy(priv[:], p[:])

	s, _ := hex.DecodeString("d3ffe2cffeba84f631c9e4f452c7f27023b48e679f30ad9f43b4ef0483670e25842efdd6a20ad74f2c08351e37857763c0e1b787a7a02c5c00708263b206ab852e865676b3b8ad2c86794cd2831b54064cda39e2703a4c172a1debf051e01ae981c58a577731127f2bfb7aaa3f9242572400")
	var sig1 [114]byte
	copy(sig1[:], s[:])

	fox := []byte("The quick brown fox jumps over the lazy dog")
	sig2 := SignWithPrivate(priv, fox)

	if bytes.Compare(sig1[:], sig2[:]) != 0 {
		t.Errorf("Signature must be %x, but it is %x", sig1, sig2)
	}
}

func TestSignSecretAndNonce(t *testing.T) {

	p, _ := hex.DecodeString("26ad14d91ef8f1e5bbf5a1a7e44a9532e4854f1e1346761ee9b4ed1ed103e5e05c87fd9ecd788bc879a7433a7115255b7aad667fe84ee35c28")
	var secret PrivateKey
	copy(secret[:], p[:])

	p, _ = hex.DecodeString("66dd9754284a1b7d77c1c43bfdfe38a116bd143e7c901b8e8e4561a7ee0a401dd5120fa2b77e2a6bda3a68d5a47e34fd29cf14ce3489067602")
	var nonce PrivateKey
	copy(nonce[:], p[:])

	s, _ := hex.DecodeString("71e4ae51aa4d1f59f10efaaca743ca557079c2de1d298375d80eac8c53d29567add49f6296206f6c0d56ad3cd3f34b3644b1b01361900bea803aae2018aea2db72a2c5557a207ba17b8316335817b4a9474def73b3ea0ddaaae593e76596fbeac45c8ef04df3bb23dc809d2b7db49dbf0a00")
	var sig1 [114]byte
	copy(sig1[:], s[:])

	fox := []byte("The quick brown fox jumps over the lazy dog")
	sig2 := SignSecretAndNonce(secret, nonce, fox)

	if bytes.Compare(sig1[:], sig2[:]) != 0 {
		t.Errorf("Signature must be %x, but it is %x", sig1, sig2)
	}
}

func TestEd448Sign(t *testing.T) {

	p, _ := hex.DecodeString("e959068474bc720bf3a94c7a524750f0d4fe68a4828137e58d48303af1fa929a6c50f87d0cab27fc557aa1a3190cfad0abbca2a2e5d7da272d")
	var priv PrivateKey
	copy(priv[:], p[:])

	s, _ := hex.DecodeString("92a7e08f86b25f288eb0308f3fb780950ab77c333d5d1b91b6de40a199fc028fe66a001dc09341905a58f8c3d4a959ee5d416735f59d91640095dd83e70b6bc05fa6a26b32c00be454bfb87285417554183c2da64bbbad77b746bd86299fd4188578bc9aa321a8291c5d2281029ca24e2d00")
	var sig1 [114]byte
	copy(sig1[:], s[:])

	fox := []byte("The quick brown fox jumps over the lazy dog")
	sig2 := Ed448Sign(priv, fox)

	if bytes.Compare(sig1[:], sig2[:]) != 0 {
		t.Errorf("Signature must be %x, but it is %x", sig1, sig2)
	}

	p, _ = hex.DecodeString("1edc2069350104b5594c602f7967c4b1580f2a757fc9a2745f621868cd333c245ec3c775d730d3c01a2e18f3e5d0b5e767ed3ec77e69732781")
	copy(priv[:], p[:])
	s, _ = hex.DecodeString("789dd9e1a4471c30cfef1da68076542e6918676424593936dbeb282f5929dcfa3437aef85fd890999ea7a1b16a2c8c3a8cf330c58768789b006b183034ec43acab783039d53fe46f6c39ab29f988a43371d07fe7746a2fd45c660f2a8c441446b8f1cdbfc0787e4cfe69280e5cd7b92d0400")
	copy(sig1[:], s[:])

	sig2 = Ed448Sign(priv, fox)

	if bytes.Compare(sig1[:], sig2[:]) != 0 {
		t.Errorf("Signature must be %x, but it is %x", sig1, sig2)
	}

}

func TestSignVerify(t *testing.T) {

	p, _ := hex.DecodeString("b93a28627cfa29fedb03c21aac0faa1ea0ba84c10cefa07c938f2e0adbf996f02c8d00e39695dfb6a0636c8bcb21645b06a869dfbbb489ef00")
	var priv PrivateKey
	copy(priv[:], p[:])

	pub := Ed448DerivePublicKey(priv)
	sig := Ed448Sign(priv, []byte{1})
	if Ed448Verify(pub, sig[:], []byte{2}) {
		t.Errorf("wrong signature verification")
	}

	pub = Ed448DerivePublicKey(priv)
	sig = Ed448Sign(priv, []byte{1})
	if !Ed448Verify(pub, sig[:], []byte{1}) {
		t.Errorf("Signature must be valid")
	}

}

func TestEd448VerifyRejectsNonCanonicalR(t *testing.T) {
	p, _ := hex.DecodeString("3d4012b96522a8d939d1d60d24c667ba76b73d0921f7b6417a6fded1aa1d6d8c53c60b9236a5939dd241e93cd51ea4a8c8d931dd9b63c13100")
	var pub PublicKey
	copy(pub[:], p[:])

	sig, _ := hex.DecodeString("92a7e08f86b25f288eb0308f3fb780950ab77c333d5d1b91b6de40a199fc028fe66a001dc09341905a58f8c3d4a959ee5d416735f59d91640168fdb4d8ddf19127e015e2db7f3485c0652652f579a8203e37059cafd3c20b61d94d5f0c960805a93c72658dd679c0ace427f431087aa00300")
	message := []byte("The quick brown fox jumps over the lazy dog")

	if Ed448Verify(pub, sig, message) {
		t.Fatalf("signature with non-canonical R must be rejected")
	}
}

func TestEd448VerifyRejectsIdentityARZeroS(t *testing.T) {
	var pub PublicKey
	pub[0] = 1
	sig := make([]byte, 114)
	sig[0] = 1

	if Ed448Verify(pub, sig, []byte{}) {
		t.Fatalf("Ed448Verify accepted identity A/R zero-S vector")
	}
}

func TestEd448VerifyAcceptsSmallOrderARZeroS(t *testing.T) {
	pub := mustPublicKeyFromHex(t, "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080")
	sig := mustDecodeHex(t, "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

	if !Ed448Verify(pub, sig, []byte{}) {
		t.Fatalf("Ed448Verify rejected small-order A/R zero-S compatibility vector")
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustPrivateKeyFromHex(t *testing.T, s string) PrivateKey {
	t.Helper()
	var key PrivateKey
	copy(key[:], mustDecodeHex(t, s))
	return key
}

func mustCanonicalPrivateKeyFromHex(t *testing.T, s string) PrivateKey {
	t.Helper()
	key := mustPrivateKeyFromHex(t, s)
	if key[56]&0x80 != 0 {
		t.Fatalf("canonical private key vector has marker bit set: %x", key[56])
	}
	return key
}

func mustPublicKeyFromHex(t *testing.T, s string) PublicKey {
	t.Helper()
	var key PublicKey
	copy(key[:], mustDecodeHex(t, s))
	return key
}

func TestCanonicalPrivateKeyVectors(t *testing.T) {
	vectors := []struct {
		name   string
		priv   string
		secret string
		pub    string
	}{
		{
			name:   "incrementing",
			priv:   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738",
			secret: "0411d38f9076da316fb9addcfe25f7c4d9403d125f3ef899409bed928bb9a30aeb9769b3b47ceba0d14ed5d7563ec01147fd18ab67cca295a8",
			pub:    "18d0a70e42a742dfb561279893385061d7b4dad8f6feed4791eaab66b2f4a4f02fc09462a8bfb1842d0bac60e8a1b3e55ba2407f33226f3800",
		},
		{
			name:   "all-01",
			priv:   "010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101",
			secret: "24c7392b799ff6e0086e4fd66c58c99fb4447771d01625ed5e9cd6cae05ffa038eab7b739c1d2ff034b474b62a1fe40c3f81841c1e807f1ceb",
			pub:    "e0758a33267939a394fb5ccb202ee851cebc2e89c91ac1289e2bfcddfd9ff9fc5694b0f569d7f7e9da16e1cde9301b29f48128b3cbd1168580",
		},
		{
			name:   "all-02",
			priv:   "020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202",
			secret: "4e8214ed3f124f0f4a713b2e57686adb349c259cd39c4d0eef22b119eec5db36b80d7ca0f7f1104b36f9f3f70054719ab546fee241a2c7fbb2",
			pub:    "b52fd5b2cb34d6f944ab81d765fa026b63fd8448b4890d025cba17308a312ae4f31a012dc08c891e9a7c3d29dbad1aaf964e6c74073249f300",
		},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			priv := mustCanonicalPrivateKeyFromHex(t, v.priv)
			secret := mustPrivateKeyFromHex(t, v.secret)
			pub := mustPublicKeyFromHex(t, v.pub)

			if got := PrivateToSecret(priv); got != secret {
				t.Fatalf("PrivateToSecret mismatch:\nwant %x\n got %x", secret, got)
			}
			if got := SecretToPublic(secret); got != pub {
				t.Fatalf("SecretToPublic mismatch:\nwant %x\n got %x", pub, got)
			}
			if got := Ed448DerivePublicKey(priv); got != pub {
				t.Fatalf("Ed448DerivePublicKey mismatch:\nwant %x\n got %x", pub, got)
			}
		})
	}
}

func TestCanonicalSignVerifyVectors(t *testing.T) {
	vectors := []struct {
		name      string
		priv      string
		pub       string
		message   []byte
		signature string
	}{
		{
			name:      "empty-message",
			priv:      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738",
			pub:       "18d0a70e42a742dfb561279893385061d7b4dad8f6feed4791eaab66b2f4a4f02fc09462a8bfb1842d0bac60e8a1b3e55ba2407f33226f3800",
			message:   []byte{},
			signature: "cb682b115cf0f0b0cf2a068acba2d0495714f2a50832739af364191c611f6983890ee133a4bf75ed2d09adc5d70f6d256b0806f3224b35d7802748b7cf55f5e9583df9f8c85db809f4877191c99ed0670ad62f54d63d7d35fddfd85efbad63554ff3ce9b847607b2f79181020880f13c1b00",
		},
		{
			name:      "zero-byte-message",
			priv:      "010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101",
			pub:       "e0758a33267939a394fb5ccb202ee851cebc2e89c91ac1289e2bfcddfd9ff9fc5694b0f569d7f7e9da16e1cde9301b29f48128b3cbd1168580",
			message:   []byte{0},
			signature: "a94e33bb28aa3b07ac36178ebe75315b7d24f9d7cab4954b190d7369a3bd4f263510cd16e5bb939e3bbd6d0561b715c18b2c2ae4bf093a0500b2690980ddcdafaeb2e14663bd1e281c3125ef8dcaa46e8af6c2515d4e42b995c639388eb464977711e1725144ab6c4eb7215142cabb3f0c00",
		},
		{
			name:      "text-message",
			priv:      "020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202",
			pub:       "b52fd5b2cb34d6f944ab81d765fa026b63fd8448b4890d025cba17308a312ae4f31a012dc08c891e9a7c3d29dbad1aaf964e6c74073249f300",
			message:   []byte("Core Ed448 compatibility test message"),
			signature: "57c1488556a9e7e780d7630203d446f655b5f742036feb2db204ee6ffa642f2c1fa112e4bd47a289d7fa95e0df5cc8ceba45ac7ac1e251bd80e5dd228fd81a95bc1ffdb8b7936c5a69cec124a07a1ed5f40bba9b8b74576154a846a73d4a282e9ae2f8d5c15044af7aa8a2c2d38028d72c00",
		},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			priv := mustCanonicalPrivateKeyFromHex(t, v.priv)
			pub := mustPublicKeyFromHex(t, v.pub)
			wantSig := mustDecodeHex(t, v.signature)
			gotSig := Ed448Sign(priv, v.message)

			if !bytes.Equal(gotSig[:], wantSig) {
				t.Fatalf("Ed448Sign mismatch:\nwant %x\n got %x", wantSig, gotSig)
			}
			if !Ed448Verify(pub, gotSig[:], v.message) {
				t.Fatalf("Ed448Verify rejected valid signature")
			}
		})
	}
}

func TestLongMessageSignVerifyVectors(t *testing.T) {
	vectors := []struct {
		name      string
		priv      string
		pub       string
		msgLen    int
		msgOffset int
		signature string
	}{
		{
			name:      "64-byte-message",
			priv:      "030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303",
			pub:       "18e2f925aef56fc05910474593ee84c932bc7ea4d352a3416f72d115e60eb58cd862f73ac50886fbaad6354a4eeb01fd9f740491fb11f59580",
			msgLen:    64,
			msgOffset: 0,
			signature: "99706c0d43655cbbdb0987520c20a2c9c98fe169d6e9ada9ed9f1167a249aff06a6c56b8147f9bda815e709cb2c2291e324042a6c1b4896b809d9dc41058be1d814bee8d55cf065a010277c96ea9a39982a95d98b7a97ade70aefb79c4b9024c16b89e5129553c11b0dc8b4894712fa73700",
		},
		{
			name:      "256-byte-message",
			priv:      "040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404",
			pub:       "4e15975a78604b2d6575f2d3310ca4e4f122226189f5900f744c1ead49408bdf8247843c05ba24fbb26c9b5f81c287cbbe3d3e8a3ad0231d00",
			msgLen:    256,
			msgOffset: 1,
			signature: "e0ffeebb9584f0be43ab16bdb6e75b08b48f9ec7029376afc8822494434a9f85eb023af5279f0bfa466fe15eabb062008fd5baaf2c61f5b180d86a810e3bae994d563d7872e3a7f85fc0d0ed8179c027527f2ccc5bc9a237ff0d659e4834e83151c02caaa8ae031d398a17cd1ae816210300",
		},
		{
			name:      "1023-byte-message",
			priv:      "050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505",
			pub:       "f4c0eecfc7f17d960823180420fb8074d882317a39a719480d3ba6e7f565fc518a4ff54ef7dca5df5de9bb3740384c84ecac265c81398c3400",
			msgLen:    1023,
			msgOffset: 2,
			signature: "9ae36ecbaece22e2f779a1818672467d34961d6028601c5e32d90d2ee1fd14b7fecd0168aeb7862b3ea6879fde654aae4670f3dc27aede2200d6f10899deede10db29a115c988005c52462a4e8cea1ff3846e581cf915b6b011d670c18abe9a7b90dc93d20ff82d53812a7c57c9dbdc33c00",
		},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			priv := mustCanonicalPrivateKeyFromHex(t, v.priv)
			pub := mustPublicKeyFromHex(t, v.pub)
			message := deterministicMessage(v.msgLen, v.msgOffset)
			wantSig := mustDecodeHex(t, v.signature)
			gotSig := Ed448Sign(priv, message)

			if !bytes.Equal(gotSig[:], wantSig) {
				t.Fatalf("Ed448Sign mismatch:\nwant %x\n got %x", wantSig, gotSig)
			}
			if !Ed448Verify(pub, gotSig[:], message) {
				t.Fatalf("Ed448Verify rejected valid long-message signature")
			}
		})
	}
}

func TestSignSecretAndNonceVectors(t *testing.T) {
	secret := mustPrivateKeyFromHex(t, "26ad14d91ef8f1e5bbf5a1a7e44a9532e4854f1e1346761ee9b4ed1ed103e5e05c87fd9ecd788bc879a7433a7115255b7aad667fe84ee35c28")
	vectors := []struct {
		name      string
		nonce     string
		message   []byte
		signature string
	}{
		{
			name:      "empty-message",
			nonce:     "66dd9754284a1b7d77c1c43bfdfe38a116bd143e7c901b8e8e4561a7ee0a401dd5120fa2b77e2a6bda3a68d5a47e34fd29cf14ce3489067602",
			message:   []byte{},
			signature: "a5fb561f2beb377e35bbf4d93b460ebeff3b55c1d64fffbcc2168c2d3998d310ed4f581499428ed46acfed19d7c8f5aa00b8fa88a7258e9c00f40ddd5e41cd33eb569d324d16babb5e840d60b6e52df10cbb2c6ea8bb3be49f39dace9cdfc7f606c2f4bfeef7bab2ab85fb787c8041302a00",
		},
		{
			name:      "zero-byte-message",
			nonce:     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738",
			message:   []byte{0},
			signature: "23a56dc2bd6db200aded4a2ad5cea6083f29b412c5575f3c4f14d53373f14b9cc03e37a3c49bfd445cd4766f7b14c3755cb6849ac357ca8880ca1a9bb804d0bab2227a0e1e8ca798f77aa59c7f98541551f6c6b5ecf89c336272e96323094b7eb5fe20cf966f94c307aab6d303f138c82500",
		},
		{
			name:      "text-message",
			nonce:     "020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202",
			message:   []byte("Core Ed448 compatibility test message"),
			signature: "2175036838bce81b72161107af10e67a39ea968ca6edfc0a1a074c3d14ae69bb7a446ca6b3c5a54727957f2bca8f2738cd8efd6a9645385500af3d2fcb330cb40e0d0252274d39c298e7c01e05cf46630872f133b99787c9069ee93dc30ec9d699e859c0cd20b7bf964aae6fa690d8713d00",
		},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			nonce := mustCanonicalPrivateKeyFromHex(t, v.nonce)
			wantSig := mustDecodeHex(t, v.signature)
			gotSig := SignSecretAndNonce(secret, nonce, v.message)

			if !bytes.Equal(gotSig[:], wantSig) {
				t.Fatalf("SignSecretAndNonce mismatch:\nwant %x\n got %x", wantSig, gotSig)
			}
		})
	}
}

func TestDeriveSecretVector(t *testing.T) {
	privA := mustCanonicalPrivateKeyFromHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738")
	pubA := mustPublicKeyFromHex(t, "18d0a70e42a742dfb561279893385061d7b4dad8f6feed4791eaab66b2f4a4f02fc09462a8bfb1842d0bac60e8a1b3e55ba2407f33226f3800")
	privB := mustCanonicalPrivateKeyFromHex(t, "582f73eb3d951ef93a8c392c7b113ad85c0f60a744c95c47370d4d593593edc0d745eb24fa2130f51fd5b1e6b2363a5405bf1e074ecbf4382d")
	pubB := mustPublicKeyFromHex(t, "4e6ef3aa2a74ce85c9c75de379c72abbce30601db4f66af1535d00190fa5de83af3831fa32e37c59e14a25788e56140896fb59b494e4fdca80")
	want := mustDecodeHex(t, "2ae0acc78a8d6e0de3e6c3fbe0cc1821bf3316e0bfd133efca8700dfceefa558979cb46730ccd42ee387f68b9416e9d35b23602fb1f24b9d")

	gotAB := Ed448DeriveSecret(pubB, privA)
	gotBA := Ed448DeriveSecret(pubA, privB)
	if !bytes.Equal(gotAB[:], want) {
		t.Fatalf("Ed448DeriveSecret A->B mismatch:\nwant %x\n got %x", want, gotAB)
	}
	if !bytes.Equal(gotBA[:], want) {
		t.Fatalf("Ed448DeriveSecret B->A mismatch:\nwant %x\n got %x", want, gotBA)
	}
}

func TestAdditionalX448Vectors(t *testing.T) {
	vectors := []struct {
		name    string
		privA   string
		pubA    string
		xPrivA  string
		xPubA   string
		privB   string
		pubB    string
		xPrivB  string
		xPubB   string
		secret  string
		addedEd string
	}{
		{
			name:    "three-four",
			privA:   "030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303",
			pubA:    "18e2f925aef56fc05910474593ee84c932bc7ea4d352a3416f72d115e60eb58cd862f73ac50886fbaad6354a4eeb01fd9f740491fb11f59580",
			xPrivA:  "9c4eff442da36181cc4a6d0e9a63a3a0018ceb85bddb4564ed6bcba2de412b4bd61e36e6d6e3f1d8a2317d23be605f52c65230caeac976b9",
			xPubA:   "ee5a4967f02d598e32540903617c4c75778dcd4fb1f133172888118b36e07cce96b286925d8f6c550ee1df767bc9b764bf078b3dbe64c2c1",
			privB:   "040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404",
			pubB:    "4e15975a78604b2d6575f2d3310ca4e4f122226189f5900f744c1ead49408bdf8247843c05ba24fbb26c9b5f81c287cbbe3d3e8a3ad0231d00",
			xPrivB:  "48043d2c79d212a4e78f0381ba33d946fb668d41dbacce6d093e4b533168e4622dc2ffc69eba5e098bab61e039b11d5e731bb2a1e1917305",
			xPubB:   "40823c9cf2dae0e9857eb8d216a1b5e8df91f3857ad09e790f1e449ff40b536fb267cba9157912bff6b3befbb238c6eae3d865ab05b64c94",
			secret:  "b5353e76df0e00c528f800f4659a7eab368f29374870979245eed3f2e9bda1351d70ca219ade1eb0b76fcea78af42268d46723ffdd9e36fb",
			addedEd: "6e99288aed0db282ae0e8d8fe03b9dc084eb201c0d6e143def07ea02d7ada39d0ae4ecea04ec451910a4c5fb2695dd1c224b0ba507b986c180",
		},
		{
			name:    "four-five",
			privA:   "040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404",
			pubA:    "4e15975a78604b2d6575f2d3310ca4e4f122226189f5900f744c1ead49408bdf8247843c05ba24fbb26c9b5f81c287cbbe3d3e8a3ad0231d00",
			xPrivA:  "48043d2c79d212a4e78f0381ba33d946fb668d41dbacce6d093e4b533168e4622dc2ffc69eba5e098bab61e039b11d5e731bb2a1e1917305",
			xPubA:   "40823c9cf2dae0e9857eb8d216a1b5e8df91f3857ad09e790f1e449ff40b536fb267cba9157912bff6b3befbb238c6eae3d865ab05b64c94",
			privB:   "050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505",
			pubB:    "f4c0eecfc7f17d960823180420fb8074d882317a39a719480d3ba6e7f565fc518a4ff54ef7dca5df5de9bb3740384c84ecac265c81398c3400",
			xPrivB:  "e9a3ec1a0dab591ce0220f7f9ac1a47b9fe3c3cdd7d50d554b868d070a9f437f07cf2b08dff6929d9ef75edf5a0a13103b19833fc695e2b0",
			xPubB:   "e333eaa9fcba294bed31ea72f41379bfe321d7713c65cb6309e6102afca0c602d15d81d07ba10312c172716de5caeed0205de7d83edeade8",
			secret:  "701b89530a21e14fb5ced445e764ee41462bc84c4ace861bdff52cbe46e17d7f1b28691af875d7ba2210d950a6876818a6869c9220231ad6",
			addedEd: "1ef1b114f0a020826789550fe32e0922d367687653aa3e4a5f32363b2ed25a3bc338d9758512c6d8e7e7d53a11005bba5db96e1fa4fe9acb80",
		},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			privA := mustCanonicalPrivateKeyFromHex(t, v.privA)
			pubA := mustPublicKeyFromHex(t, v.pubA)
			privB := mustCanonicalPrivateKeyFromHex(t, v.privB)
			pubB := mustPublicKeyFromHex(t, v.pubB)
			wantXPrivA := mustDecodeHex(t, v.xPrivA)
			wantXPubA := mustDecodeHex(t, v.xPubA)
			wantXPrivB := mustDecodeHex(t, v.xPrivB)
			wantXPubB := mustDecodeHex(t, v.xPubB)
			wantSecret := mustDecodeHex(t, v.secret)
			wantAdded := mustPublicKeyFromHex(t, v.addedEd)

			gotXPrivA := EdPrivateKeyToX448(privA)
			gotXPubA := EdPublicKeyToX448(pubA)
			gotXPrivB := EdPrivateKeyToX448(privB)
			gotXPubB := EdPublicKeyToX448(pubB)
			gotSecretAB := Ed448DeriveSecret(pubB, privA)
			gotSecretBA := Ed448DeriveSecret(pubA, privB)
			gotAdded := addTwoPublic(pubA, pubB)

			if !bytes.Equal(gotXPrivA[:], wantXPrivA) || !bytes.Equal(gotXPubA[:], wantXPubA) {
				t.Fatalf("A X448 conversion mismatch")
			}
			if !bytes.Equal(gotXPrivB[:], wantXPrivB) || !bytes.Equal(gotXPubB[:], wantXPubB) {
				t.Fatalf("B X448 conversion mismatch")
			}
			if !bytes.Equal(gotSecretAB[:], wantSecret) || !bytes.Equal(gotSecretBA[:], wantSecret) {
				t.Fatalf("Ed448DeriveSecret mismatch")
			}
			if gotAdded != wantAdded {
				t.Fatalf("addTwoPublic mismatch:\nwant %x\n got %x", wantAdded, gotAdded)
			}
		})
	}
}

func TestNegativeVerifyVectors(t *testing.T) {
	pub := mustPublicKeyFromHex(t, "18d0a70e42a742dfb561279893385061d7b4dad8f6feed4791eaab66b2f4a4f02fc09462a8bfb1842d0bac60e8a1b3e55ba2407f33226f3800")
	otherPub := mustPublicKeyFromHex(t, "e0758a33267939a394fb5ccb202ee851cebc2e89c91ac1289e2bfcddfd9ff9fc5694b0f569d7f7e9da16e1cde9301b29f48128b3cbd1168580")
	signature := mustDecodeHex(t, "cb682b115cf0f0b0cf2a068acba2d0495714f2a50832739af364191c611f6983890ee133a4bf75ed2d09adc5d70f6d256b0806f3224b35d7802748b7cf55f5e9583df9f8c85db809f4877191c99ed0670ad62f54d63d7d35fddfd85efbad63554ff3ce9b847607b2f79181020880f13c1b00")

	mutatedR := append([]byte(nil), signature...)
	mutatedR[0] ^= 0x01
	mutatedS := append([]byte(nil), signature...)
	mutatedS[57] ^= 0x01
	invalidR := append([]byte(nil), signature...)
	for i := 0; i < 57; i++ {
		invalidR[i] = 0xff
	}
	nonCanonicalR := append([]byte(nil), signature...)
	copy(nonCanonicalR[:57], nonCanonicalEd448EncodingP())
	var zeroPub PublicKey
	zeroSig := make([]byte, 114)
	var invalidPub PublicKey
	for i := range invalidPub {
		invalidPub[i] = 0xff
	}
	var nonCanonicalPub PublicKey
	copy(nonCanonicalPub[:], nonCanonicalEd448EncodingP())

	vectors := []struct {
		name    string
		pub     PublicKey
		sig     []byte
		message []byte
	}{
		{name: "wrong-message", pub: pub, sig: signature, message: []byte{0}},
		{name: "wrong-public-key", pub: otherPub, sig: signature, message: []byte{}},
		{name: "mutated-r", pub: pub, sig: mutatedR, message: []byte{}},
		{name: "mutated-s", pub: pub, sig: mutatedS, message: []byte{}},
		{name: "zero-public-key", pub: zeroPub, sig: signature, message: []byte{}},
		{name: "zero-signature", pub: pub, sig: zeroSig, message: []byte{}},
		{name: "zero-public-key-and-signature", pub: zeroPub, sig: zeroSig, message: []byte{}},
		{name: "invalid-public-key", pub: invalidPub, sig: signature, message: []byte{}},
		{name: "invalid-r", pub: pub, sig: invalidR, message: []byte{}},
		{name: "non-canonical-public-key-y-ge-p", pub: nonCanonicalPub, sig: signature, message: []byte{}},
		{name: "non-canonical-r-y-ge-p", pub: pub, sig: nonCanonicalR, message: []byte{}},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			if Ed448Verify(v.pub, v.sig, v.message) {
				t.Fatalf("Ed448Verify accepted negative vector %q", v.name)
			}
		})
	}
}

func deterministicMessage(length int, offset int) []byte {
	message := make([]byte, length)
	for i := range message {
		message[i] = byte((i + offset) & 0xff)
	}
	return message
}

func nonCanonicalEd448EncodingP() []byte {
	encoding := make([]byte, 57)
	for i := 0; i < 56; i++ {
		encoding[i] = 0xff
	}
	encoding[28] = 0xfe
	return encoding
}
