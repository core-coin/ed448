package ed448

import (
	"bytes"
	"testing"
	"encoding/hex"
	crand "crypto/rand"
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

func TestAddTwoPublic(t *testing.T) {

	p, _ := hex.DecodeString("5475efbfc0fa155f3fd80a8c183260eef996532fd084899e32df9cb8db9eb34410d2ea0d4f8b273fbd79c3276b50b70fea40732ad88f45de00")
	var pub1 PublicKey
	copy(pub1[:], p[:])


	p, _ = hex.DecodeString("d666091b1b3836d082d349e66521878cf7afc734329d5d132d8ebd06bebf6514aaad5794dbafed3fd6aa1c5d59d5db914e8460041ff3db6280")
	var pub2 PublicKey
	copy(pub2[:], p[:])

	p, _ = hex.DecodeString("6af04e1137833cbf82878fcdcd8310851fe582320690990a7497de63389311588d4c0d4d6fce79d07958824e54ef11fabd23b815c81e79ea80")
	var pub PublicKey
	copy(pub[:], p[:])

	generatedKey := AddTwoPublic(pub1, pub2)
	
	if bytes.Compare(pub[:], generatedKey[:]) != 0 {
		t.Errorf("Public key must be %x, but it is %x", generatedKey, pub)
	}
}
