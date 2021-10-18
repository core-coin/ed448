package mobile

import (
	"bytes"

	"github.com/core-coin/ed448"
)

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

func Ed448Verify(pubKey, signature, message string) (bool, error) {
	pb, err := decodeBytes(pubKey)
	if err != nil {
		return false, err
	}
	pub := ed448.BytesToPublicKey(pb)

	sig, err := decodeBytes(signature)
	if err != nil {
		return false, err
	}

	msg, err := decodeBytes(message)
	if err != nil {
		return false, err
	}

	return ed448.Ed448Verify(pub, sig, msg), nil
}
