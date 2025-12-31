package iso7816

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestCommandAPDU_Encoding(t *testing.T) {
	// Setup base objects
	cls, _ := NewClass(0x00)
	insSelect, _ := NewInstruction(INS_SELECT)
	insRead, _ := NewInstruction(INS_READ_BINARY)

	tests := []struct {
		name     string
		cmd      *CommandAPDU
		expected string
	}{
		{
			name:     "Case 1: Header Only (No Data, No Le)",
			cmd:      NewCommandAPDU(cls, insSelect, 0x01, 0x02, nil, 0),
			expected: "00A40102",
		},
		{
			name: "Case 2 Short: Data < MaxShortLc",
			cmd:  NewCommandAPDU(cls, insSelect, 0x04, 0x00, []byte{0xA0, 0x00}, 0),
			// Lc=02, Data=A000
			expected: "00A4040002A000",
		},
		{
			name: "Case 3 Short: No Data, Le=MaxShortLe (256)",
			cmd:  NewCommandAPDU(cls, insRead, 0x00, 0x00, nil, MaxShortLe),
			// Le=00 means 256 in Short mode
			expected: "00B0000000",
		},
		{
			name: "Case 4 Short: Data and Le",
			cmd:  NewCommandAPDU(cls, insSelect, 0x00, 0x00, []byte{0x01}, 10),
			// Lc=01, Data=01, Le=0A
			expected: "00A4000001010A",
		},
		{
			name: "Case 2 Extended: Data > MaxShortLc",
			cmd: func() *CommandAPDU {
				longData := make([]byte, 260) // 260 bytes > 255
				return NewCommandAPDU(cls, insSelect, 0x00, 0x00, longData, 0)
			}(),
			// Lc Extended: 00 (Flag) + 0104 (Len 260) + Data...
			expected: "00A40000000104" + hex.EncodeToString(make([]byte, 260)),
		},
		{
			name: "Case 3 Extended: No Data, Le=MaxExtendedLe (65536)",
			cmd:  NewCommandAPDU(cls, insRead, 0x00, 0x00, nil, MaxExtendedLe),
			// Lc absent (00 Flag for Le) + Le Extended (0000 for 65536)
			expected: "00B00000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBytes, err := tt.cmd.Bytes()
			if err != nil {
				t.Fatalf("Encoding failed: %v", err)
			}
			gotHex := strings.ToUpper(hex.EncodeToString(gotBytes))
			expectedHex := strings.ToUpper(tt.expected)

			if gotHex != expectedHex {
				// Display truncated strings for readability
				dispGot := gotHex
				dispExp := expectedHex
				if len(dispGot) > 50 {
					dispGot = dispGot[:20] + "..." + dispGot[len(dispGot)-10:]
					dispExp = dispExp[:20] + "..." + dispExp[len(dispExp)-10:]
				}
				t.Errorf("Mismatch\nExpected: %s\nGot:      %s", dispExp, dispGot)
			}
		})
	}
}

func TestParseResponseAPDU(t *testing.T) {
	// Raw: 01 02 03 (Data) | 90 00 (SW)
	raw, _ := hex.DecodeString("0102039000")
	resp, err := ParseResponseAPDU(raw)

	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(resp.Data) != 3 {
		t.Errorf("Wrong data length: got %d, want 3", len(resp.Data))
	}
	if resp.Status != SW_NO_ERROR {
		t.Errorf("Wrong status: got %04X, want %04X", uint16(resp.Status), uint16(SW_NO_ERROR))
	}
}

func TestParseResponseAPDU_TooShort(t *testing.T) {
	// Only 1 byte, should fail
	raw := []byte{0x90}
	_, err := ParseResponseAPDU(raw)

	if err == nil {
		t.Error("Expected error for short response, got nil")
	}
}
