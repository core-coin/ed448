package ed448

import (

	"fmt"
	"io"

//	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

type ExtendedPrivate [114]uint8
type ExtendedPublic [114]uint8

func SHA512Hash(password, salt []uint8) []uint8 {

	return pbkdf2.Key(password, salt, 2048, 57, sha3.New512)

}

func concatenateAndHex(prefix uint8, key []uint8, index uint32, salt []uint8) []uint8 {

	if len(key) != 57 {
		panic("wrong slice length")
	}


	var p [62]uint8
	p[0] = prefix

	copy(p[1:58], key[:])

	for i := 58; i < 62; i++ {
		p[i] = uint8(index & 0xff)
		index >>= 8
	}

	return SHA512Hash(p[:], salt)
}

func addTwoSecrets(secKey1 []uint8, secKey2 []uint8) []uint8 {

	if len(secKey1) != 57 {
		panic("wrong slice length")
	}
	if len(secKey2) != 57 {
		panic("wrong slice length")
	}

	var secKey [57]uint8
	var count uint16 = 0
	for i := 0; i < 57; i++ {
		count += uint16(secKey1[i]) + uint16(secKey2[i])
		secKey[i] = uint8(count & 0xff)
		count >>= 8
	}
	return secKey[:]
}

func addTwoPublic(pub1 PublicKey, pub2 PublicKey) PublicKey {

	var pub PublicKey
	p := NewPoint([16]uint32{}, [16]uint32{}, [16]uint32{}, [16]uint32{})
	p1 := NewPoint([16]uint32{}, [16]uint32{}, [16]uint32{}, [16]uint32{})
	p2 := NewPoint([16]uint32{}, [16]uint32{}, [16]uint32{}, [16]uint32{})

	if !p1.EdDSADecode(pub1[:]) {
		panic("Point is not on the curve!")
	}
	if !p2.EdDSADecode(pub2[:]) {
		panic("Point is not on the curve!")
	}
	p.Add(p1, p2)

	r := p.EdDSAEncode()

	copy(pub[:], r[:])

	return pub
}

func shiftPublic(pub1 PublicKey, shift []uint8) PublicKey {

	r := NewScalar(shift[:])
	r.Halve(r)
	r.Halve(r)
	p2 := PrecomputedScalarMul(r)

	var pub PublicKey
	p := NewPoint([16]uint32{}, [16]uint32{}, [16]uint32{}, [16]uint32{})
	p1 := NewPoint([16]uint32{}, [16]uint32{}, [16]uint32{}, [16]uint32{})

	if !p1.EdDSADecode(pub1[:]) {
		panic("Point is not on the curve!")
	}
	p.Add(p1, p2)

	t := p.EdDSAEncode()

	copy(pub[:], t[:])

	return pub
}



func clampTemplate(t []uint8) {

	if len(t) != 57 {
		panic("wrong slice length")
	}

	t[56] = 0
	t[55] = 0
	t[54] = 0
	t[53] = 0
	t[0] &= 0xfc
}

func SeedToExtendedPrivate(s [114]uint8) ExtendedPrivate {
	var p ExtendedPrivate
	copy(p[:], s[:])
	p[113] |= 0x80 // Set key type identifier
	p[112] |= 0x80 // EdDSA standard
	p[112] &= 0xbf // Set to keep previous =1 during generation new accounts

	return p
}

func (s ExtendedPrivate) getPublic() PublicKey {
	var secret PrivateKey
	copy(secret[:], s[57:])
	var public PublicKey = SecretToPublic(secret)

	var zero [57]uint8
	copy(secret[:], zero[:])

	return public
}

func ExtendedPrivateToPublic(s ExtendedPrivate) ExtendedPublic {
	var pub ExtendedPublic
	copy(pub[:57], s[:57])
	p := s.getPublic()
	copy(pub[57:], p[:])
	return pub
}

func ChildPrivateToPrivate(s ExtendedPrivate, index uint32) ExtendedPrivate {
	var child ExtendedPrivate

	if index >= 0x80000000 {
		hex := concatenateAndHex(1, s[57:], index, s[:57])
		copy(child[:57], hex[:])

		var zero [57]uint8
		copy(hex[:], zero[:])

		hex = concatenateAndHex(0, s[57:], index, s[:57])
		clampTemplate(hex)
		var a []uint8 = addTwoSecrets(s[57:], hex)
		copy(child[57:], a[:])

		copy(hex[:], zero[:])
		copy(a[:], zero[:])

		return child
	} else {
		var pub PublicKey = s.getPublic()
		hex := concatenateAndHex(3, pub[:], index, s[:57])
		copy(child[:57], hex[:])

		var zero [57]uint8
		copy(hex[:], zero[:])

		hex = concatenateAndHex(2, pub[:], index, s[:57])
		clampTemplate(hex)
		var a []uint8 = addTwoSecrets(s[57:], hex)
		copy(child[57:], a[:])

		copy(hex[:], zero[:])
		copy(a[:], zero[:])

		return child
	}
}

func ChildPrivateToPublic(s ExtendedPrivate, index uint32) ExtendedPublic {
	var s1 ExtendedPrivate = ChildPrivateToPrivate(s, index)
	var p ExtendedPublic = ExtendedPrivateToPublic(s1)
	var zero [114]uint8
	copy(s1[:], zero[:])
	return p
}

func ChildPublicToPublic(pub ExtendedPublic, index uint32) ExtendedPublic {
	if index >= 0x80000000 {
		panic("wrong index value")
	}
	var child ExtendedPublic

	hex := concatenateAndHex(3, pub[57:], index, pub[:57])
	copy(child[:57], hex[:])

	hex = concatenateAndHex(2, pub[57:], index, pub[:57])
	clampTemplate(hex)
/*	var s1 PrivateKey
	copy(s1[:], hex[:])
	a2 := publicWithoutClamp(s1)*/


	var a1 PublicKey
	copy(a1[:], pub[57:])
	var a PublicKey = shiftPublic(a1, hex[:])
	copy(child[57:], a[:])

	return child
}



func GenerateSeed(reader io.Reader) ([114]uint8, error) {
	seed := new([114]uint8)
	n, err := io.ReadFull(reader, seed[:])
	if err != nil {
		return [114]uint8{}, err
	} else if n != 114 {
		return [114]uint8{}, fmt.Errorf("not 114 random bytes")
	}
	return *seed, nil 
}