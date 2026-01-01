package iso7816

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/gregLibert/smart-card/pkg/tlv"
)

func TestNewReadRecordCommand(t *testing.T) {
	cls, _ := NewClass(0x00)

	tests := []struct {
		name     string
		cmd      *CommandAPDU
		expected []byte
	}{
		{
			name: "Read Record 1 from SFI 1 (Standard EMV)",
			cmd:  ReadRecord(cls, 1, 1),
			expected: tlv.Hex(
				"00 B2 01 0C", // Header
				"00",          // Le=256
			),
		},
		{
			name: "Read Record 5 from Current EF",
			cmd:  ReadRecord(cls, 0, 5),
			expected: tlv.Hex(
				"00 B2 05 04",
				"00",
			),
		},
		{
			name: "Read All Records starting from 1 (SFI 2)",
			cmd:  ReadAllRecords(cls, 2, 1),
			expected: tlv.Hex(
				"00 B2 01 15",
				"00",
			),
		},
		{
			name: "Read Next Occurrence by ID (SFI 10)",
			cmd:  NewReadRecordCommand(cls, 10, 0xAA, RefByID_NextOccurrence),
			expected: tlv.Hex(
				"00 B2 AA 52",
				"00",
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cmd.Bytes()
			if err != nil {
				t.Fatalf("Failed to encode bytes: %v", err)
			}

			if !bytes.Equal(got, tt.expected) {
				t.Errorf("Mismatch:\nExpected: %s\nGot:      %s",
					hex.EncodeToString(tt.expected),
					hex.EncodeToString(got))
			}
		})
	}
}
