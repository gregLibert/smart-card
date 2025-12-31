package tlv

import (
	"bytes"
	"testing"
)

func TestHex(t *testing.T) {
	tests := []struct {
		name      string
		inputs    []string
		want      []byte
		wantPanic bool
	}{
		{
			name:   "Simple Join",
			inputs: []string{"00", "A4"},
			want:   []byte{0x00, 0xA4},
		},
		{
			name:   "With Spaces",
			inputs: []string{"00 A4", " 04 00 "},
			want:   []byte{0x00, 0xA4, 0x04, 0x00},
		},
		{
			name:   "Mixed Case",
			inputs: []string{"ca", "FE"},
			want:   []byte{0xCA, 0xFE},
		},
		{
			name:      "Invalid Hex",
			inputs:    []string{"ZZ"},
			wantPanic: true,
		},
		{
			name:      "Odd Length",
			inputs:    []string{"123"},
			wantPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if (r != nil) != tt.wantPanic {
					t.Errorf("Hex() panic = %v, wantPanic %v", r, tt.wantPanic)
				}
			}()

			got := Hex(tt.inputs...)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("Hex() = %X, want %X", got, tt.want)
			}
		})
	}
}
