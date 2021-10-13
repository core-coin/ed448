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

func PointBySecret(p PrivateKey) Point {

	digest := [57]byte{}
	copy(digest[:], p[:])
	clamp(digest[:])

	r := NewScalar(digest[:])
	r.Halve(r)
	r.Halve(r)
	h := PrecomputedScalarMul(r)

	Zero := PrivateKey{0}
	copy(digest[:], Zero[:])

	return h
}

// SLICES TO KEYS

func BytesToPublicKey(key []byte) (pk PublicKey) {
	if len(key) != len(PublicKey{}) {
		return PublicKey{}
	}
	copy(pk[:], key)
	return
}

func BytesToPrivateKey(key []byte) (pk PrivateKey) {
	if len(key) != len(PrivateKey{}) {
		return PrivateKey{}
	}
	copy(pk[:], key)
	return
}

// DIFFIE-HELLMAN SHARED SECRET

func EdPrivateKeyToX448(edKey PrivateKey) [56]byte {
	x := [56]byte{}
	sha3.ShakeSum256(x[:], edKey[:])
	return x
}

func EdPublicKeyToX448(edKey PublicKey) [56]byte {
	return fromEdDSATox448(edKey[:])
}

func Ed448DeriveSecret(pubkey PublicKey, privkey PrivateKey) [56]byte {

	var xpriv = [56]byte{0}
	if privkey[57-1]&0x80 == 0x00 {
		xpriv = EdPrivateKeyToX448(privkey)
	} else {
		copy(xpriv[:], privkey[0:56])
	}

	xpub := EdPublicKeyToX448(pubkey)
	a, b := x448ScalarMul(xpub[:], xpriv[:])
	if !b {
		panic("Diffie-Hellman: result must not be zero")
	}
	return a
}

// PRIVATE, SECRET AND PUBLIC

func PrivateToSecret(pk PrivateKey) PrivateKey {

	var sk PrivateKey
	sha3.ShakeSum256(sk[:], pk[:])
	sk[56] |= 0x80
	return sk
}

func SecretToPublic(sk PrivateKey) PublicKey {

	var s1 PrivateKey
	copy(s1[:], sk[:])
	clamp(s1[:])
	r := NewScalar(s1[:])
	r.Halve(r)
	r.Halve(r)
	h := PrecomputedScalarMul(r)

	var pub PublicKey
	p := h.EdDSAEncode()
	copy(pub[:], p[:])

	Zero := PrivateKey{0}
	copy(s1[:], Zero[:])
	return pub
}

func PrivateToPublic(privkey PrivateKey) PublicKey {
	var pub PublicKey
	p := PointByPrivate(privkey).EdDSAEncode()
	copy(pub[:], p[:])
	return pub
}

func Ed448DerivePublicKey(privkey PrivateKey) PublicKey {
	if privkey[57-1]&0x80 == 0x00 {
		return PrivateToPublic(privkey)
	} else {
		return SecretToPublic(privkey)
	}
}

// CREATE SIGNATURE

func SignWithPrivate(privkey PrivateKey, message []byte) [114]byte {

	return DSASign(privkey, PointByPrivate(privkey), message)
}

func SignSecretAndNonce(secret, n PrivateKey, msg []byte) [114]byte {

	var s1 PrivateKey
	copy(s1[:], secret[:])
	clamp(s1[:])

	pub := PointBySecret(secret)

	sec := NewScalar(s1[:])
	seed := n[:]

	nonce := make([]byte, 114)
	hashWithDom(nonce, append(seed, msg...))
	nonceScalar := NewScalar(nonce[:])
	nonceScalar2 := NewScalar()
	nonceScalar2.Halve(nonceScalar)
	nonceScalar2.Halve(nonceScalar2)
	noncePoint := PrecomputedScalarMul(nonceScalar2).EdDSAEncode()

	challenge := make([]byte, 114)
	hashWithDom(challenge, append(append(noncePoint, pub.EdDSAEncode()...), msg...))

	challengeScalar := NewScalar(challenge)
	challengeScalar.Mul(challengeScalar, sec)
	challengeScalar.Add(challengeScalar, nonceScalar)

	var sig [114]byte
	copy(sig[:], noncePoint)
	copy(sig[57:], challengeScalar.Encode())

	Zero := PrivateKey{0}
	copy(s1[:], Zero[:])

	return sig
}

func Ed448Sign(privkey PrivateKey, message []byte) [114]byte {

	if privkey[57-1]&0x80 == 0x00 {
		return SignWithPrivate(privkey, message)
	} else {
		var sk PrivateKey
		copy(sk[:], privkey[:])
		clamp(sk[:])

		sig := SignSecretAndNonce(sk, sk, message)

		// Erasing temporary values of private keys
		var sZero = PrivateKey{0}
		copy(sk[:], sZero[:])

		return sig
	}
}

// VERIFY SIGNATURE

func Ed448Verify(pubkey PublicKey, signature, message []byte) bool {

	p := NewPoint([16]uint32{}, [16]uint32{}, [16]uint32{}, [16]uint32{})

	if !p.EdDSADecode(pubkey[:]) {
		return false
	}
	var sig [114]byte
	copy(sig[:], signature[:])

	return DSAVerify(sig, p, message)
}

// GENERATE PRIVATE KEY

func Ed448GenerateKey(reader io.Reader) (PrivateKey, error) {
	key := new(PrivateKey)
	n, err := io.ReadFull(reader, key[:])
	if err != nil {
		return PrivateKey{}, err
	} else if n != 57 {
		return PrivateKey{}, fmt.Errorf("not 57 random bytes")
	}
	key[56] &= 0x7f
	return *key, nil
}
