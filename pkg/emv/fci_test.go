package emv

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/gregLibert/smart-card/pkg/tlv"
)

func TestParseFCI(t *testing.T) {
	tests := []struct {
		name      string
		rawData   []byte
		wantLabel string
		wantDF    string
		wantErr   bool
	}{
		{
			name: "Standard EMV FCI",
			rawData: tlv.Hex(
				"6F 1A",                      // FCI Template
				"84 07 A0000000041010",       // DF Name
				"A5 0F",                      // Proprietary Template
				"50 0A 4D617374657243617264", // Label "MasterCard"
				"87 01 01",                   // Priority 1
			),
			wantLabel: "MasterCard",
			wantDF:    "A0000000041010",
		},
		{
			name: "FCI without 6F wrapper (Direct TLV)",
			rawData: tlv.Hex(
				"84 0E 325041592E5359532E4444463031", // DF Name (2PAY.SYS.DDF01)
				"A5 08",
				"88 01 02",     // SFI 2
				"5F2D 02 656E", // Language "en"
			),
			wantDF: "325041592E5359532E4444463031",
		},
		{
			name:    "Empty Data",
			rawData: []byte{},
			wantErr: true,
		},
		{
			name:    "Invalid TLV",
			rawData: []byte{0x6F, 0x05, 0x84}, // Incomplete
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseFCI(tt.rawData)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseFCI() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			if got == nil {
				t.Fatal("Expected result, got nil")
			}

			if tt.wantDF != "" {
				df := strings.ToUpper(hex.EncodeToString(got.DFName))
				if df != tt.wantDF {
					t.Errorf("DFName mismatch. Got %s, want %s", df, tt.wantDF)
				}
			}

			if tt.wantLabel != "" {
				lbl := string(got.ProprietaryTemplate.ApplicationLabel)
				if lbl != tt.wantLabel {
					t.Errorf("Label mismatch. Got %s, want %s", lbl, tt.wantLabel)
				}
			}
		})
	}
}

func TestFCI_Describe(t *testing.T) {
	rawData := tlv.Hex(
		"6F 31",                                // FCI Template (Len 49)
		"84 07 A0000000031010",                 // DF Name (VISA)
		"A5 26",                                // Proprietary Template (Len 38)
		"50 04 56495341",                       // App Label: "VISA"
		"BF0C 17",                              // Issuer Discretionary Data (Len 23)
		"5F50 0E 7777772E6D795F62616E6B2E6575", // URL: "www.my_bank.eu"
		"99 04 11223344",                       // Unknown Tag inside BF0C (Discretionary)
		"9F38 03 9F1A02",                       // PDOL inside A5 (Proprietary)
	)

	fci, err := ParseFCI(rawData)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	report := fci.Describe()
	actualLines := strings.Split(report, "\n")

	// Define the exact expected lines based on tlv.WriteStructFields format
	expectedLines := []string{
		"=== EMV FCI TEMPLATE ===",
		`    - FCI.DFName (84): A0000000031010 (".......")`,
		`    - Proprietary.ApplicationLabel (50): 56495341 ("VISA")`,
		`    - Proprietary.PDOL (9F38): 9F1A02`,
		`    - Discretionary.IssuerURL (5F50): 7777772E6D795F62616E6B2E6575 ("www.my_bank.eu")`,
		`    - Discretionary.Unknown Tag 99: 11223344`,
	}

	if diff := cmp.Diff(expectedLines, actualLines); diff != "" {
		t.Errorf("Report mismatch (-want +got):\n%s", diff)
	}
}
