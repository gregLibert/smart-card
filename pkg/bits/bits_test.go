package bits

import "testing"

func TestBit(t *testing.T) {
	tests := []struct {
		n        uint
		expected byte
	}{
		{1, 0x01}, {5, 0x10}, {8, 0x80}, {0, 0x00},
		{9, 0x00}, //dumb value silently ignored
	}

	for _, tt := range tests {
		if res := Bit(tt.n); res != tt.expected {
			t.Errorf("Bit(%d) = 0x%02X; want 0x%02X", tt.n, res, tt.expected)
		}
	}
}

func TestIsSet(t *testing.T) {
	val := byte(0b10100101)
	if !IsSet(val, 8) {
		t.Error("Bit 8 should be set")
	}
	if IsSet(val, 7) {
		t.Error("Bit 7 should NOT be set")
	}
	if !IsSet(val, 1) {
		t.Error("Bit 1 should be set")
	}
}

func TestGetRange(t *testing.T) {
	tests := []struct {
		name     string
		input    byte
		high     uint
		low      uint
		expected byte
	}{
		{"Bits 4-3 of 0x0C", 0b0000_1100, 4, 3, 3},
		{"Bits 2-1 of 0x03", 0b0000_0011, 2, 1, 3},
		{"Bits 4-1 of 0x0F", 0b0000_1111, 4, 1, 15},
		{"Bits 8-7 of 0x40", 0b0100_0000, 8, 7, 1},
		{"Full Byte", 0xAA, 8, 1, 0xAA},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if res := GetRange(tt.input, tt.high, tt.low); res != tt.expected {
				t.Errorf("GetRange(0x%02X, %d, %d) = %d; want %d", tt.input, tt.high, tt.low, res, tt.expected)
			}
		})
	}
}

func TestSet(t *testing.T) {
	var b byte = 0
	b = Set(b, 5)
	expected := byte(1 << 4)
	if b != expected {
		t.Errorf("Set(5) = 0b%08b; want 0b%08b", b, expected)
	}
}
