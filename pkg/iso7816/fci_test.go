package iso7816

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/gregLibert/smart-card/pkg/tlv"
)

func TestParseSelectData(t *testing.T) {
	// P2 constants: Selection control is on bits 4 and 3.
	const (
		P2_FCI     byte = 0b0000_00_00
		P2_FCP     byte = 0b0000_01_00
		P2_FMD     byte = 0b0000_10_00
		P2_NO_DATA byte = 0b0000_11_00
	)

	tests := []struct {
		name      string
		rawData   []byte
		p2        byte
		wantAID   string
		wantLabel string
		wantErr   bool
		check     func(*FileControlInfo) bool
	}{
		{
			name: "FCI with FCP (62) wrapped in 6F",
			rawData: tlv.Hex(
				"6F 09",            // FCI Template (Len 9)
				"62 07",            // FCP Template (Len 7)
				"84 05 A000000001", // AID
			),
			p2:      P2_FCI,
			wantAID: "A000000001",
		},
		{
			name: "FCI with FMD (64) wrapped in 6F",
			rawData: tlv.Hex(
				"6F 07",        // FCI Template (Len 7)
				"64 05",        // FMD Template (Len 5)
				"50 03 414243", // Label "ABC"
			),
			p2:        P2_FCI,
			wantLabel: "ABC",
		},
		{
			name: "Direct FCP Request (Mandatory 62)",
			rawData: tlv.Hex(
				"62 07",            // FCP Template (Len 7)
				"84 05 A000000002", // AID
			),
			p2:      P2_FCP,
			wantAID: "A000000002",
		},
		{
			name: "Direct FMD Request (Mandatory 64)",
			rawData: tlv.Hex(
				"64 05",        // FMD Template (Len 5)
				"50 03 58595A", // Label "XYZ"
			),
			p2:        P2_FMD,
			wantLabel: "XYZ",
		},
		{
			name: "Error: Mismatch P2 vs Data",
			rawData: tlv.Hex(
				"64 05",        // Received FMD
				"50 03 58595A", // Label
			),
			p2:      P2_FCP, // But requested FCP
			wantErr: true,
		},
		{
			name:    "Proprietary Response (C0)",
			rawData: tlv.Hex("C0 01 FF"),
			p2:      P2_FCI,
			check: func(fci *FileControlInfo) bool {
				return fci.ProprietaryRawData != nil
			},
		},
		{
			name: "Fallback: No Template",
			rawData: tlv.Hex(
				"84 05 A000000003", // Raw AID tag
			),
			p2:      P2_FCI,
			wantAID: "A000000003",
		},
		{
			name: "Unknown Tag Capture in FCP",
			rawData: tlv.Hex(
				"62 0B",            // FCP Template (Len 11)
				"84 05 A000000004", // AID (7 bytes total)
				"99 02 CAFE",       // Unknown Tag 99 (4 bytes total)
			),
			p2:      P2_FCP,
			wantAID: "A000000004",
			check: func(fci *FileControlInfo) bool {
				if len(fci.FCP.Unknown) != 1 {
					return false
				}
				tag := fci.FCP.Unknown[0]
				return tag.Tag == "99" && hex.EncodeToString(tag.Value) == "cafe"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSelectData(tt.rawData, tt.p2)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSelectData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if got == nil {
				t.Fatal("Expected result, got nil")
			}

			if tt.wantAID != "" {
				aid := strings.ToUpper(hex.EncodeToString(got.GetAID()))
				if aid != tt.wantAID {
					t.Errorf("AID mismatch. Got %s, want %s", aid, tt.wantAID)
				}
			}

			if tt.wantLabel != "" {
				label := string(got.ApplicationLabel())
				if label != tt.wantLabel {
					t.Errorf("Label mismatch. Got %s, want %s", label, tt.wantLabel)
				}
			}

			if tt.check != nil {
				if !tt.check(got) {
					t.Errorf("Custom check failed")
				}
			}
		})
	}
}
