package tlv

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/moov-io/bertlv"
)

type MockTemplate struct {
	FileID     []byte `tlv:"84"`
	Label      []byte `tlv:"50" fmt:"ascii"`
	Priority   []byte `tlv:"87" fmt:"int"`
	RawData    []byte // No tag
	EmptyField []byte `tlv:"99"`
	Unknown    []bertlv.TLV
}

func TestWriteStructFields(t *testing.T) {
	mock := MockTemplate{
		FileID:   []byte{0xA0, 0x00, 0x01},
		Label:    []byte{'V', 'I', 'S', 'A', 0x00},
		Priority: []byte{0x01},
		RawData:  []byte{0xCA, 0xFE},
		Unknown: []bertlv.TLV{
			{Tag: "9F01", Value: []byte{0x12, 0x34}},
		},
	}

	tests := []struct {
		name          string
		prefix        string
		input         interface{}
		expectedLines []string
	}{
		{
			name:   "Struct Pointer Input",
			prefix: "Test",
			input:  &mock,
			expectedLines: []string{
				"    - Test.FileID (84): A00001",
				`    - Test.Label (50): 5649534100 ("VISA.")`,
				"    - Test.Priority (87): 01 (Dec: 1)",
				"    - Test.RawData: CAFE",
				"    - Test.Unknown Tag 9F01: 1234",
			},
		},
		{
			name:   "Struct Value Input",
			prefix: "Val",
			input:  mock,
			expectedLines: []string{
				"    - Val.FileID (84): A00001",
				`    - Val.Label (50): 5649534100 ("VISA.")`,
				"    - Val.Priority (87): 01 (Dec: 1)",
				"    - Val.RawData: CAFE",
				"    - Val.Unknown Tag 9F01: 1234",
			},
		},
		{
			name:          "Nil Pointer",
			prefix:        "Nil",
			input:         (*MockTemplate)(nil),
			expectedLines: []string{""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sb strings.Builder
			WriteStructFields(&sb, tt.prefix, tt.input)
			actualLines := strings.Split(sb.String(), "\n")

			if diff := cmp.Diff(tt.expectedLines, actualLines); diff != "" {
				t.Errorf("Mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMakeSafeASCII(t *testing.T) {
	input := []byte{0x41, 0x42, 0x00, 0x1F, 0x7F, 0x43} // AB, null, US, DEL, C
	want := "AB...C"                                    // 0x7F (127) is > 126, so it becomes dot

	got := MakeSafeASCII(input)
	if got != want {
		t.Errorf("MakeSafeASCII() = %q, want %q", got, want)
	}
}
