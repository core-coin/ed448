package ed448

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestXprivFromSeed(t *testing.T) {
	p1, _ := hex.DecodeString("6bc0169565eecbc8e62259959534a67684adbd4c229cc8830405fe81f60c7b896a273421c9587f4b3321ab8353bf7178b8f383ce07f916de7abebabfef0f5fee")
	var seed [64]uint8
	copy(seed[:], p1[:])

	key, _ := SeedToXprvData(seed[:], 0)
	keyString := key.B58Serialize()
	xpriv := "xprv44jU3WStrxLpqTPjfJhEm5YWSnxHXWT1nxAz2LZucufEACdLtu2kbMFhkrHk4QzY3VNv1J4JpL9KQykmWeAaacHkL9azdG1uxDzG9cip6ngsFUs2kacE1eAfFVFTBMDsPR1BAy3NMpE7jZuTXfLL3ippnRRBuoJ6BcNykWCJHJ6e6Y"

	if keyString != xpriv {
		t.Errorf("xPriv must be %s, but it is %s", xpriv, keyString)
	}
}

func TestXprivDecode(t *testing.T) {
	xpriv := "xprv44jU3WStrxLpqTPjfJhEm5YWSnxHXWT1nxAz2LZucufEACdLtu2kbMFhkrHk4QzY3VNv1J4JpL9KQykmWeAaacHkL9azdG1uxDzG9cip6ngsFUs2kacE1eAfFVFTBMDsPR1BAy3NMpE7jZuTXfLL3ippnRRBuoJ6BcNykWCJHJ6e6Y"
	key, err := B58Deserialize(xpriv)
	if !reflect.DeepEqual(err, nil) {
		t.Errorf("Error during deserialization")
	}
	key1 := &Key{
		Key:         []byte{97, 241, 220, 103, 103, 117, 60, 169, 219, 126, 212, 28, 50, 167, 69, 215, 147, 1, 33, 254, 186, 1, 185, 185, 173, 10, 103, 116, 220, 144, 110, 135, 117, 195, 238, 219, 38, 3, 126, 76, 47, 252, 236, 204, 25, 141, 246, 249, 127, 156, 127, 45, 121, 184, 155, 175, 133},
		Version:     PrivateMainnetVersion,
		ChildNumber: []byte{0x00, 0x00, 0x00, 0x00},
		FingerPrint: []byte{0x00, 0x00, 0x00, 0x00},
		ChainCode:   []byte{52, 135, 40, 198, 127, 136, 39, 197, 250, 193, 124, 129, 193, 124, 186, 36, 92, 149, 126, 225, 109, 17, 93, 239, 24, 2, 203, 57, 214, 55, 251, 104, 32, 71, 176, 84, 243, 235, 75, 22, 148, 119, 216, 69, 179, 180, 215, 200, 127, 163, 110, 195, 231, 233, 141, 12, 3},
		Depth:       0,
		IsPrivate:   true,
	}

	if !reflect.DeepEqual(key, key1) {
		t.Errorf("Master xprv is invalid")
	}
}

func TestXprivToXpub(t *testing.T) {
	xpriv := "xprv44jU3WStrxLpqTPjfJhEm5YWSnxHXWT1nxAz2LZucufEACdLtu2kbMFhkrHk4QzY3VNv1J4JpL9KQykmWeAaacHkL9azdG1uxDzG9cip6ngsFUs2kacE1eAfFVFTBMDsPR1BAy3NMpE7jZuTXfLL3ippnRRBuoJ6BcNykWCJHJ6e6Y"
	key, err := B58Deserialize(xpriv)
	if !reflect.DeepEqual(err, nil) {
		t.Errorf("Error during deserialization")
	}

	key, err = key.PublicKey()

	key1 := &Key{
		Key:         []byte{255, 122, 32, 83, 51, 55, 109, 90, 94, 232, 92, 90, 135, 182, 85, 101, 53, 254, 220, 212, 197, 143, 117, 102, 131, 222, 118, 64, 126, 80, 94, 222, 217, 158, 89, 120, 248, 216, 74, 83, 224, 71, 172, 92, 163, 228, 211, 157, 205, 13, 101, 10, 201, 171, 117, 224, 0},
		Version:     PublicMainnetVersion,
		ChildNumber: []byte{0x00, 0x00, 0x00, 0x00},
		FingerPrint: []byte{0x00, 0x00, 0x00, 0x00},
		ChainCode:   []byte{52, 135, 40, 198, 127, 136, 39, 197, 250, 193, 124, 129, 193, 124, 186, 36, 92, 149, 126, 225, 109, 17, 93, 239, 24, 2, 203, 57, 214, 55, 251, 104, 32, 71, 176, 84, 243, 235, 75, 22, 148, 119, 216, 69, 179, 180, 215, 200, 127, 163, 110, 195, 231, 233, 141, 12, 3},
		Depth:       0,
		IsPrivate:   false,
	}

	if !reflect.DeepEqual(key.Key, key1.Key) {
		t.Errorf("Master xpub is invalid")
	}
}

func TestXprivSerializeDeserialize(t *testing.T) {
	xpriv := "xprv44jU3WStrxLpqTPjfJhEm5YWSnxHXWT1nxAz2LZucufEACdLtu2kbMFhkrHk4QzY3VNv1J4JpL9KQykmWeAaacHkL9azdG1uxDzG9cip6ngsFUs2kacE1eAfFVFTBMDsPR1BAy3NMpE7jZuTXfLL3ippnRRBuoJ6BcNykWCJHJ6e6Y"
	key, err := B58Deserialize(xpriv)
	if !reflect.DeepEqual(err, nil) {
		t.Errorf("Error during deserialization")
	}
	xpriv1 := key.B58Serialize()
	if xpriv != xpriv1 {
		t.Errorf("Serialization failed")
	}
}

func TestXpubSerializeDeserialize(t *testing.T) {
	xpub := "xpub5qaJDytXEfWWEb5zBzW8YBZ5ZbmBrV2z7DRtcR2qqqRM3qnDUC43XZANq9YPurzuDjjJ1xkfhsskDiaidX7z9Df5Rrtige1rcWHzTvkZGEYqUoqWREvUQshd4FRcgKTHsEFyjLTtFUL9hGVA8cYERqYQxUhcFS1Ts1a1KnPZj4g1u1"
	key, err := B58Deserialize(xpub)
	if !reflect.DeepEqual(err, nil) {
		t.Errorf("Error during deserialization")
	}
	xpub1 := key.B58Serialize()
	if xpub != xpub1 {
		t.Errorf("Serialization failed")
	}
}

func TestDiamond(t *testing.T) {
	xpriv := "xprv44jU3WStrxLpqTPjfJhEm5YWSnxHXWT1nxAz2LZucufEACdLtu2kbMFhkrHk4QzY3VNv1J4JpL9KQykmWeAaacHkL9azdG1uxDzG9cip6ngsFUs2kacE1eAfFVFTBMDsPR1BAy3NMpE7jZuTXfLL3ippnRRBuoJ6BcNykWCJHJ6e6Y"
	key, _ := B58Deserialize(xpriv)
	key1, _ := key.PublicKey()
	key2, _ := key.NewChildKeyData(1)
	key3, _ := key2.PublicKey()
	key4, _ := key1.NewChildKeyData(1)

	if !reflect.DeepEqual(key3, key4) {
		t.Errorf("Diamond test failed")
	}
}
