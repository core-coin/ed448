package ed448

import (
	"bytes"
	"testing"
	"encoding/hex"
	crand "crypto/rand"
)

func TestSeedToExtendedPrivate(t *testing.T) {

	p1, _ := hex.DecodeString("004e843c2991930124e5a0711c6a8be763f5b605ee80f089dfa9cbec5ebb20123dcc787b162a7baf37b0251f6bdd4ac14ae111491ef391cf0d22769f20360cd7840e55ab1f282f066cc94c1e2c08e4235f68b170cfc92f6b6a546bb7da1de112c0e730ce5456bd76df620b571bfbfc95467f")
	var seed [114]uint8
	copy(seed[:], p1[:])


	p2, _ := hex.DecodeString("004e843c2991930124e5a0711c6a8be763f5b605ee80f089dfa9cbec5ebb20123dcc787b162a7baf37b0251f6bdd4ac14ae111491ef391cf0d22769f20360cd7840e55ab1f282f066cc94c1e2c08e4235f68b170cfc92f6b6a546bb7da1de112c0e730ce5456bd76df620b571bfbfc9586ff")

	generatedKey := SeedToExtendedPrivate(seed)
	
	if bytes.Compare(p2[:], generatedKey[:]) != 0 {
		t.Errorf("Extended private must be: %x\n But it is: %x", p2, generatedKey)
	}

}

func TestExtendedPrivateToPublic(t *testing.T) {

	p1, _ := hex.DecodeString("004e843c2991930124e5a0711c6a8be763f5b605ee80f089dfa9cbec5ebb20123dcc787b162a7baf37b0251f6bdd4ac14ae111491ef391cf0d1413821ed67083c855c6db4405dd4fa5fdec39e1c761be1415623c1c202c5cb5176e578830372b7e07eb1ef9cf71b19518815c4da0fd2d3594")
	var seed [114]uint8
	copy(seed[:], p1[:])


	p2, _ := hex.DecodeString("004e843c2991930124e5a0711c6a8be763f5b605ee80f089dfa9cbec5ebb20123dcc787b162a7baf37b0251f6bdd4ac14ae111491ef391cf0db615e57dd4d15c3ed1323725c0ba8b1d7f6e740d08e0e29c6d3ff564c896c0c3dd28a9bb5065e06725c8f9e3f7c2c6bbad4900b7447ecf9880")

	generatedKey := ExtendedPrivateToPublic(seed)
	
	if bytes.Compare(p2[:], generatedKey[:]) != 0 {
		t.Errorf("Extended private must be: %x\n But it is: %x", p2, generatedKey)
	}

}

func TestChildPrivateToPrivate(t *testing.T) {

	p1, _ := hex.DecodeString("757a4a352e3aafdad7f65f6bf4f150800d334ffcac56e719cc3412ae6ae5a2f547f2b587785ac52c0136a09f05bbe43b6b000e3f9c49f7f7c76a103854fa8597b9514a0d6b11e0e972d492c0fd61afe5fb5baa38d51406ba333c7e5a7c43a121b694d6694047e6433e05c372a5eb78a48e99")
	var e ExtendedPrivate
	copy(e[:], p1[:])


	p2, _ := hex.DecodeString("b8254111ddf243fd897b44878678ff15d16763c7939e86512fd2b6d6535fde62ec6c94dd61fc76033d94e001ea26ef3950a0edd2ef74713760e63a36576ee565e08646a99c2062ebdf773167dc533a0a3a1b0d929d8b77b5faf7d54d557f3b537eeb572b04b04d246fb63154381679a48e99")

	generatedKey := ChildPrivateToPrivate(e, 0)
	
	if bytes.Compare(p2[:], generatedKey[:]) != 0 {
		t.Errorf("Child private must be: %x\n But it is: %x", p2, generatedKey)
	}

	p1, _ = hex.DecodeString("88b8592017482e0d85a8c405b84e12ba3a8ac552198216b0da811adc368589cc86a8bb38c67c766f9a942e7cedf5a6a36338f3d5bdd9466e2554b229028a76f79a18f4171fea287db096f05cc62ff3246ec70a2ebbf896b094350650846703183c09a13790e93fd3110c3ec0fe338daf93ba")
	copy(e[:], p1[:])

	p2, _ = hex.DecodeString("bd9c963ce9ac0fb9da7f9dfa0ea84251ed6f3eba924858bb7b2f9eb3a66aa4fb42a87a0d5b05c9a48c442b480477d17cd89b8679acd6ccdf02fca262c2f9a158d51bea28d0b2724f237560f65a3b8ae98215dc97ade43beb1e3dad4fc12ec8a81da661db0ab6b94f1c566e38f16e8daf93ba")

	generatedKey = ChildPrivateToPrivate(e, 0x80000000)
	
	if bytes.Compare(p2[:], generatedKey[:]) != 0 {
		t.Errorf("Child private must be: %x\n But it is: %x", p2, generatedKey)
	}
}

func TestChildPublicToPublic(t *testing.T) {

	p1, _ := hex.DecodeString("08288c75a01cafb05193567fb285b66767a6d393b7763f3f085f140ac0ad59b56dfdae70533f112a67cbd359910b2c5f1c8916bf6f593a5db4e7e1d0e85a354edc803d39f89923aadd362da91693cbb01206b86b3173039e18513a9964f96f34aa27b275d9a81b50905ebc860905e1c51700")
	var e ExtendedPublic
	copy(e[:], p1[:])


	p2, _ := hex.DecodeString("0c051354b0efede7fa00124dd9e5a37bb7f0edf157b8139f64be5f6cac2c5edc7c60e1c4245136e9b9b8ea7f9ef5ab20032f6c6f2dba07d7f44a5aa538883ce7a9115337293eedb620ee031b71e994936557e58ef1dbafd1f91413c154b8713c43150a14e11c0ce0ba1d6d55bd26802d2080")

	generatedKey := ChildPublicToPublic(e, 0)
	
	if bytes.Compare(p2[:], generatedKey[:]) != 0 {
		t.Errorf("Child private must be: %x\n But it is: %x", p2, generatedKey)
	}
}


func TestRandomCompare(t *testing.T) {

	s, _ := GenerateSeed(crand.Reader)
	priv := SeedToExtendedPrivate(s)
	pub := ExtendedPrivateToPublic(priv)
	priv1 := ChildPrivateToPrivate(priv, 0)
	pub1 := ChildPublicToPublic(pub, 0)
	pub2 := ExtendedPrivateToPublic(priv1)

	if bytes.Compare(pub1[:], pub2[:]) != 0 {
		t.Errorf("Child keys, generated from seed: \n%x\n are\n%x\nand\n%x\n", s,pub1,pub2)
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

	generatedKey := addTwoPublic(pub1, pub2)
	
	if bytes.Compare(pub[:], generatedKey[:]) != 0 {
		t.Errorf("Public key must be %x, but it is %x", generatedKey, pub)
	}
}
