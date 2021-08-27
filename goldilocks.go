package ed448

import (
	"fmt"
	"io"

	"golang.org/x/crypto/sha3"
)

type PublicKey [57]byte
type PrivateKey [57]byte

func PointByPrivate(p PrivateKey) Point {

	digest := [57]byte{}
	sha3.ShakeSum256(digest[:], p[:])
	clamp(digest[:])

	r := NewScalar(digest[:])
	r.Halve(r)
	r.Halve(r)
	h := PrecomputedScalarMul(r)

	return h
}

func EdPrivateKeyToX448(edKey PrivateKey) [56]byte {
	x := [56]byte{}
	sha3.ShakeSum256(x[:], edKey[:])
	return x
}

func EdPublicKeyToX448(edKey PublicKey) [56]byte {
	return fromEdDSATox448(edKey[:])
}

func Ed448DeriveSecret(pubkey PublicKey, privkey PrivateKey) [56]byte {
	xpriv := EdPrivateKeyToX448(privkey)
	xpub := EdPublicKeyToX448(pubkey)
	a, b := x448ScalarMul(xpub[:], xpriv[:])
	if !b {
		panic("Diffie-Hellman: result must not be zero")
	}
	return a
}

func Ed448DerivePublicKey(privkey PrivateKey) PublicKey {
	var pub PublicKey
	p := PointByPrivate(privkey).EdDSAEncode()
	copy(pub[:], p[:])
	return pub
}

func Ed448Sign(privkey PrivateKey, pubkey PublicKey, message, context []byte, prehashed bool) [114]byte {
	if len(context) != 0 {
		panic("Context is not supported!")
	}
	if prehashed {
		panic("Prehashing is not supported!")
	}
	p := NewPoint([16]uint32{}, [16]uint32{}, [16]uint32{}, [16]uint32{})

	if !p.EdDSADecode(pubkey[:]) {
		panic("Point is not on the curve!")
	}
	return DSASign(privkey, p, message)
}

func Ed448Verify(pubkey PublicKey, signature, message, context []byte, prehashed bool) bool {
	if len(context) != 0 {
		panic("Context is not supported!")
	}
	if prehashed {
		panic("Prehashing is not supported!")
	}
	p := NewPoint([16]uint32{}, [16]uint32{}, [16]uint32{}, [16]uint32{})

	if !p.EdDSADecode(pubkey[:]) {
		panic("Point is not on the curve!")
	}
	var sig [114]byte
	copy(sig[:], signature[:])

	return DSAVerify(sig, p, message)
}

func Ed448GenerateKey(reader io.Reader) (PrivateKey, error) {
	key := new(PrivateKey)
	n, err := io.ReadFull(reader, key[:])
	if err != nil {
		return PrivateKey{}, err
	} else if n != 57 {
		return PrivateKey{}, fmt.Errorf("not 57 random bytes")
	}
	return *key, nil
}
