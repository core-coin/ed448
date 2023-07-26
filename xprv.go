package ed448

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"

	"github.com/FactomProject/basen"
	"golang.org/x/crypto/ripemd160"
)

type Key struct {
	Key         []byte // 57 bytes
	Version     []byte // 4 bytes
	ChildNumber []byte // 4 bytes
	FingerPrint []byte // 4 bytes
	ChainCode   []byte // 57 bytes
	Depth       byte   // 1 bytes
	IsPrivate   bool   // unserialized
}

const (
	Mainnet int = 0
	Devin       = 1
)

var (
	// PrivateMainnetVersion is the version flag for serialized private keys in mainnet
	PrivateMainnetVersion, _ = hex.DecodeString("0658299C")

	// PublicMainnetVersion is the version flag for serialized private keys in mainnet
	PublicMainnetVersion, _ = hex.DecodeString("06582F87")

	// PrivateTest etVersion is the version flag for serialized private keys in testnet
	PrivateTestnetVersion, _ = hex.DecodeString("05E3C9A2")

	// PublicTestnetVersion is the version flag for serialized private keys in mainnet
	PublicTestnetVersion, _ = hex.DecodeString("05E3CF8D")

	// ErrSerializedKeyWrongSize is returned when trying to deserialize a key that
	// has an incorrect length
	ErrSerializedKeyWrongSize = errors.New("Serialized keys should by exactly 131 bytes")

	// ErrHardnedChildPublicKey is returned when trying to create a harded child
	// of the public key
	ErrHardnedChildPublicKey = errors.New("Can't create hardened child for public key")

	// ErrInvalidChecksum is returned when deserializing a key with an incorrect
	// checksum
	ErrInvalidChecksum = errors.New("Checksum doesn't match")

	// ErrInvalidPrivateKey is returned when a derived private key is invalid
	ErrInvalidPrivateKey = errors.New("Invalid private key")

	// ErrInvalidPrivateKey is returned when try to derive public from public
	ErrKeyIsNotPrivate = errors.New("Not a private key")

	// ErrInvalidPublicKey is returned when a derived public key is invalid
	ErrInvalidPublicKey = errors.New("Invalid public key")

	// ErrInvalidPublicKey is returned when a network is not implemented
	ErrInvalidNetwork = errors.New("Invalid network")

	BitcoinBase58Encoding = basen.NewEncoding("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
)

func hashSha256(data []byte) ([]byte, error) {
	hasher := sha256.New()
	_, err := hasher.Write(data)
	if err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func hashDoubleSha256(data []byte) ([]byte, error) {
	hash1, err := hashSha256(data)
	if err != nil {
		return nil, err
	}

	hash2, err := hashSha256(hash1)
	if err != nil {
		return nil, err
	}
	return hash2, nil
}

func hashRipeMD160(data []byte) ([]byte, error) {
	hasher := ripemd160.New()
	_, err := io.WriteString(hasher, string(data))
	if err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func hash160(data []byte) ([]byte, error) {
	hash1, err := hashSha256(data)
	if err != nil {
		return nil, err
	}

	hash2, err := hashRipeMD160(hash1)
	if err != nil {
		return nil, err
	}

	return hash2, nil
}

func checksum(data []byte) ([]byte, error) {
	hash, err := hashDoubleSha256(data)
	if err != nil {
		return nil, err
	}

	return hash[:4], nil
}

func addChecksumToBytes(data []byte) ([]byte, error) {
	checksum, err := checksum(data)
	if err != nil {
		return nil, err
	}
	return append(data, checksum...), nil
}

func base58Encode(data []byte) string {
	return BitcoinBase58Encoding.EncodeToString(data)
}

func base58Decode(data string) ([]byte, error) {
	return BitcoinBase58Encoding.DecodeString(data)
}

func uint32Bytes(i uint32) []byte {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, i)
	return bytes
}

func SeedToXprvData(s []uint8, network int) (*Key, error) {
	extendedPrivate := SeedToExtendedPrivate(s)
	chainCode := extendedPrivate[:57]
	keyBytes := extendedPrivate[57:]
	var networkPrefix []byte
	switch network {
	case Mainnet:
		networkPrefix = PrivateMainnetVersion[:]
	case Devin:
		networkPrefix = PrivateTestnetVersion
	default:
		return nil, ErrInvalidNetwork
	}
	key := &Key{
		Version:     networkPrefix,
		ChainCode:   chainCode,
		Key:         keyBytes,
		Depth:       0x0,
		ChildNumber: []byte{0x00, 0x00, 0x00, 0x00},
		FingerPrint: []byte{0x00, 0x00, 0x00, 0x00},
		IsPrivate:   true,
	}
	return key, nil
}
func (key *Key) NewChildKeyData(childIdx uint32) (*Key, error) {
	// Fail early if trying to create hardned child from public key
	if !key.IsPrivate && childIdx >= 0x80000000 {
		return nil, ErrHardnedChildPublicKey
	}

	childKey := &Key{
		ChildNumber: uint32Bytes(childIdx),
		Depth:       key.Depth + 1,
		IsPrivate:   key.IsPrivate,
		Version:     key.Version,
	}

	if key.IsPrivate {
		var p ExtendedPrivate
		copy(p[:57], key.ChainCode)
		copy(p[57:], key.Key)
		pChild := ChildPrivateToPrivate(p, childIdx)
		childKey.ChainCode = pChild[:57]
		childKey.Key = pChild[57:]
		pub := p.getPublic()
		fingerprint, err := hash160(pub[:])
		if err != nil {
			return nil, err
		}
		childKey.FingerPrint = fingerprint[:4]
	} else {
		var p ExtendedPublic
		copy(p[:57], key.ChainCode)
		copy(p[57:], key.Key)
		pChild := ChildPublicToPublic(p, childIdx)
		childKey.ChainCode = pChild[:57]
		childKey.Key = pChild[57:]
		fingerprint, err := hash160(p[57:])
		if err != nil {
			return nil, err
		}
		childKey.FingerPrint = fingerprint[:4]
	}

	return childKey, nil
}

func (key *Key) PublicKey() (*Key, error) {

	if !key.IsPrivate {
		return nil, ErrKeyIsNotPrivate
	}

	var priv ExtendedPrivate
	copy(priv[:57], key.ChainCode)
	copy(priv[57:], key.Key)
	pub := priv.getPublic()

	var networkPrefix []byte
	if bytes.Equal(key.Version, PrivateMainnetVersion) {
		networkPrefix = PublicMainnetVersion
	} else if bytes.Equal(key.Version, PrivateTestnetVersion) {
		networkPrefix = PublicTestnetVersion
	} else {
		return nil, ErrInvalidNetwork
	}

	xpub := &Key{
		Version:     networkPrefix,
		Key:         pub[:],
		Depth:       key.Depth,
		ChildNumber: key.ChildNumber,
		FingerPrint: key.FingerPrint,
		ChainCode:   key.ChainCode,
		IsPrivate:   false,
	}

	return xpub, nil
}

func (key *Key) Serialize() ([]byte, error) {
	keyBytes := key.Key

	// Write fields to buffer in order
	buffer := new(bytes.Buffer)
	buffer.Write(key.Version)
	buffer.WriteByte(key.Depth)
	buffer.Write(key.FingerPrint)
	buffer.Write(key.ChildNumber)
	buffer.Write(key.ChainCode)
	buffer.Write(keyBytes)

	// Append the standard doublesha256 checksum
	serializedKey, err := addChecksumToBytes(buffer.Bytes())
	if err != nil {
		return nil, err
	}

	return serializedKey, nil
}

func (key *Key) B58Serialize() string {
	serializedKey, err := key.Serialize()
	if err != nil {
		return ""
	}

	return base58Encode(serializedKey)
}

func Deserialize(data []byte) (*Key, error) {
	if len(data) != 131 {
		return nil, ErrSerializedKeyWrongSize
	}
	var key = &Key{}
	key.Version = data[0:4]
	key.Depth = data[4]
	key.FingerPrint = data[5:9]
	key.ChildNumber = data[9:13]
	key.ChainCode = data[13:70]
	key.Key = data[70:127]

	if bytes.Equal(key.Version, PrivateMainnetVersion) || bytes.Equal(key.Version, PrivateTestnetVersion) {
		key.IsPrivate = true
	} else if bytes.Equal(key.Version, PublicMainnetVersion) || bytes.Equal(key.Version, PublicTestnetVersion) {
		key.IsPrivate = false
	} else {
		return nil, ErrInvalidNetwork
	}

	// validate checksum
	cs1, err := checksum(data[0 : len(data)-4])
	if err != nil {
		return nil, err
	}

	cs2 := data[len(data)-4:]
	for i := range cs1 {
		if cs1[i] != cs2[i] {
			return nil, ErrInvalidChecksum
		}
	}
	return key, nil
}

func B58Deserialize(data string) (*Key, error) {
	b, err := base58Decode(data)
	if err != nil {
		return nil, err
	}
	return Deserialize(b)
}
