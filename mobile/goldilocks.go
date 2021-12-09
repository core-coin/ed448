package mobile

import (
	"bytes"
	"strconv"

	"github.com/core-coin/ed448"
)

func Ed448HDWalletsGenerateKey(seed string, index string) (string, error) {
	sb, err := decodeBytes(seed)
	if err != nil {
		return "", err
	}

	iu, err := strconv.ParseUint(index, 10, 32)
	if err != nil {
		return "", err
	}

	m := ed448.SeedToExtendedPrivate([]uint8(sb))
	k1 := ed448.ChildPrivateToPrivate(m, 0x80000000+44)
	k2 := ed448.ChildPrivateToPrivate(k1, 0x80000000+654)
	k3 := ed448.ChildPrivateToPrivate(k2, 0x80000000+0)
	k4 := ed448.ChildPrivateToPrivate(k3, 0x80000000+0)
	k5 := ed448.ChildPrivateToPrivate(k4, uint32(iu))

	return encodeBytes(k5[57:]), nil
}

func Ed448GenerateKey(seed string) (string, error) {
	sb, err := decodeBytes(seed)
	if err != nil {
		return "", err
	}

	privKey, err := ed448.Ed448GenerateKey(bytes.NewBuffer(sb))
	if err != nil {
		return "", err
	}

	return encodeBytes(privKey[:]), nil
}

func Ed448DerivePublicKey(privKey string) (string, error) {
	pb, err := decodeBytes(privKey)
	if err != nil {
		return "", err
	}
	priv := ed448.BytesToPrivateKey(pb)

	pub := ed448.Ed448DerivePublicKey(priv)
	return encodeBytes(pub[:]), nil
}

func Ed448Sign(privKey, message string) (string, error) {
	pb, err := decodeBytes(privKey)
	if err != nil {
		return "", err
	}
	priv := ed448.BytesToPrivateKey(pb)

	msg, err := decodeBytes(message)
	if err != nil {
		return "", err
	}

	sig := ed448.Ed448Sign(priv, msg)
	return encodeBytes(sig[:]), nil
}

func Ed448Verify(pubKey, signature, message string) (string, error) {
	pb, err := decodeBytes(pubKey)
	if err != nil {
		return "false", err
	}
	pub := ed448.BytesToPublicKey(pb)

	sig, err := decodeBytes(signature)
	if err != nil {
		return "false", err
	}

	msg, err := decodeBytes(message)
	if err != nil {
		return "false", err
	}

	if !ed448.Ed448Verify(pub, sig, msg) {
		return "false", nil
	}
	return "true", nil
}
