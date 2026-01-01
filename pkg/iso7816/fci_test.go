package iso7816

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/gregLibert/smart-card/pkg/tlv"
)

//nolint:gocyclo // Test function with many table-driven cases, complexity is expected.
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
		// custom check for complex logic verification
		check func(*FileControlInfo) error
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
			name: "Flat FCI: Mixed FCP, FMD and Unknown Tags",
			// Scenario: No 62/64 wrapper. Tags are mixed at root level.
			rawData: tlv.Hex(
				"82 01 38",     // FCP: File Descriptor (Tag 82)
				"50 03 544553", // FMD: Application Label "TES" (Tag 50)
				"99 02 CAFE",   // UNKNOWN: Tag 99
			),
			p2:        P2_FCI,
			wantLabel: "TES",
			check: func(fci *FileControlInfo) error {
				if hex.EncodeToString(fci.FCP.FileDescriptor) != "38" {
					return fmt.Errorf("FCP FileDescriptor mismatch: got %x, want 38", fci.FCP.FileDescriptor)
				}
				if len(fci.FCP.Unknown) != 0 {
					return fmt.Errorf("FCP.Unknown should be empty in flat mode, got %d items", len(fci.FCP.Unknown))
				}
				if len(fci.FMD.Unknown) != 0 {
					return fmt.Errorf("FMD.Unknown should be empty in flat mode, got %d items", len(fci.FMD.Unknown))
				}
				if len(fci.Unknown) != 1 {
					return fmt.Errorf("FCI.Unknown should contain exactly 1 item, got %d", len(fci.Unknown))
				}
				if fci.Unknown[0].Tag != "99" {
					return fmt.Errorf("Expected Unknown Tag 99, got %s", fci.Unknown[0].Tag)
				}
				return nil
			},
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
			check: func(fci *FileControlInfo) error {
				if fci.ProprietaryRawData == nil {
					return fmt.Errorf("ProprietaryRawData should not be nil")
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSelectData(tt.rawData, tt.p2)

			// Check error expectation
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

			// Verify AID helper
			if tt.wantAID != "" {
				aid := strings.ToUpper(hex.EncodeToString(got.GetAID()))
				if aid != tt.wantAID {
					t.Errorf("AID mismatch. Got %s, want %s", aid, tt.wantAID)
				}
			}

			// Verify Label helper
			if tt.wantLabel != "" {
				label := string(got.ApplicationLabel())
				if label != tt.wantLabel {
					t.Errorf("Label mismatch. Got %s, want %s", label, tt.wantLabel)
				}
			}

			// Run custom check if defined
			if tt.check != nil {
				if err := tt.check(got); err != nil {
					t.Errorf("Custom check failed: %v", err)
				}
			}
		})
	}
}
