package bits

// Bit returns a byte with only the n-th bit set (1 to 8).
func Bit(n uint) byte {
	if n < 1 || n > 8 {
		return 0
	}
	return 1 << (n - 1)
}

// IsSet checks if the n-th bit is set (1 to 8).
func IsSet(b byte, n uint) bool {
	return b&Bit(n) != 0
}

// GetRange extracts the value from a range of bits (e.g., bits 4 to 3).
// Example: GetRange(0b00001100, 4, 3) returns 3 (0b11)
func GetRange(b byte, high, low uint) byte {
	if high < low || high > 8 || low < 1 {
		return 0
	}

	width := high - low + 1
	mask := byte((1 << width) - 1)

	return (b >> (low - 1)) & mask
}

// Set active le bit n.
func Set(b byte, n uint) byte {
	return b | Bit(n)
}
