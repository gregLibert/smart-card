package iso7816

import (
	"strings"
	"testing"
)

func TestNewInstruction(t *testing.T) {
	tests := []struct {
		name    string
		ins     InsCode
		wantErr bool
		check   func(Instruction) bool
	}{
		{
			name: "Standard SELECT (A4)",
			ins:  0xA4,
			check: func(i Instruction) bool {
				return i.Raw == INS_SELECT && !i.IsBERTLV
			},
		},
		{
			name: "Read Binary BER-TLV (B1)",
			ins:  0b1011_0001,
			check: func(i Instruction) bool {
				return i.Raw == INS_READ_BINARY_BER && i.IsBERTLV
			},
		},
		{
			name:    "Invalid INS 6X",
			ins:     0x6A,
			wantErr: true,
		},
		{
			name:    "Invalid INS 9X",
			ins:     0x90,
			wantErr: true,
		},
		{
			name: "Create File (E0)",
			ins:  0xE0,
			check: func(i Instruction) bool {
				return !i.IsBERTLV
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewInstruction(tt.ins)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewInstruction(0x%02X) error = %v, wantErr %v", byte(tt.ins), err, tt.wantErr)
				return
			}
			if !tt.wantErr && !tt.check(got) {
				t.Errorf("NewInstruction(0x%02X) failed validation: %+v", byte(tt.ins), got)
			}
		})
	}
}

func TestInstruction_Verbose(t *testing.T) {
	// Tests stringer integration and formatting
	tests := []struct {
		ins      InsCode
		contains []string
	}{
		{INS_SELECT, []string{"INS: 0xA4", "Command: INS_SELECT", "Format: Standard"}},
		{INS_READ_BINARY_BER, []string{"INS: 0xB1", "Command: INS_READ_BINARY_BER", "Format: BER-TLV"}},
	}

	for _, tt := range tests {
		i, _ := NewInstruction(tt.ins)
		desc := i.Verbose()
		for _, part := range tt.contains {
			if !strings.Contains(desc, part) {
				t.Errorf("Verbose() = %q; want containing %q", desc, part)
			}
		}
	}
}
