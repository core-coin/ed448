package mobile

import (
	"encoding/hex"
	"strings"
)

func decodeBytes(code string) ([]byte, error) {
	code = strings.TrimPrefix(code, "0x")
	return hex.DecodeString(code)
}

func encodeBytes(data []byte) string {
	return "0x" + hex.EncodeToString(data)
}
