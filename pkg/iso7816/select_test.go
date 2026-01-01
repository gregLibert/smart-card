package iso7816

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/gregLibert/smart-card/pkg/tlv"
)

func TestNewSelectCommand(t *testing.T) {
	cls, _ := NewClass(0x00)

	tests := []struct {
		name     string
		cmd      *CommandAPDU
		expected []byte
	}{
		{
			name: "Select by AID (1PAY.SYS.DDF01)",
			cmd:  SelectByAID(cls, []byte("1PAY.SYS.DDF01")),
			expected: tlv.Hex(
				"00 A4 04 00", // Header: CLA=00, INS=A4, P1=04 (AID), P2=00
				"0E",          // Lc=14
				"31 50 41 59 2E 53 59 53 2E 44 44 46 30 31", // Data: "1PAY.SYS.DDF01"
				// NO Le "00" here due to T=0 compatibility
			),
		},
		{
			name: "Select Master File (MF)",
			cmd:  SelectMF(cls),
			expected: tlv.Hex(
				"00 A4 00 00", // Header: CLA=00, INS=A4, P1=00 (FileID), P2=00
				"00",          // Le=256 (Allowed because no data sent)
			),
		},
		{
			name: "Select Next Occurrence FCP",
			cmd: NewSelectCommand(
				cls,
				SelectByFileID,
				NextOccurrence,
				ReturnFCP,
				[]byte{0x3F, 0x00},
			),
			expected: tlv.Hex(
				"00 A4 00 06", // Header: P2=06 (ReturnFCP 04 | Next 02)
				"02",          // Lc=2
				"3F 00",       // Data: File ID 3F00
				// NO Le "00" here due to T=0 compatibility
			),
		},
		{
			name: "Select No Data",
			cmd: NewSelectCommand(
				cls,
				SelectByFileID,
				FirstOrOnlyOccurrence,
				ReturnNoData,
				[]byte{0x3F, 0x00},
			),
			expected: tlv.Hex(
				"00 A4 00 0C", // Header: P2=0C (ReturnNoData 0C | First 00)
				"02",          // Lc=2
				"3F 00",       // Data: File ID 3F00
				// Le absent
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
