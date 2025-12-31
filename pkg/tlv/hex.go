package tlv

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Hex constructs a byte slice from a series of hex strings.
func Hex(parts ...string) []byte {
	fullHex := strings.Join(parts, "")
	// Clean up spaces to allow format like "00 A4 04 00"
	cleanHex := strings.ReplaceAll(fullHex, " ", "")

	data, err := hex.DecodeString(cleanHex)
	if err != nil {
		panic(fmt.Sprintf("invalid input '%s': %v", cleanHex, err))
	}
	return data
}
