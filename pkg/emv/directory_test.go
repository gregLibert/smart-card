package emv

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/gregLibert/smart-card/pkg/tlv"
)

func TestParseDirectoryRecord_WithUnknowns(t *testing.T) {
	rawData := tlv.Hex(
		"70 2E",                                // Record Template (70) containing:
		"99 02 DEAF",                           // Unknown Tag 99
		"61 28",                                // App Template
		"4F 07 A0000000031010",                 // AID
		"50 04 56495341",                       // App Label: "VISA"
		"73 17",                                // Directory Discretionary Template
		"5F50 0E 7777772E6D795F62616E6B2E6575", // URL: "www.my_bank.eu"
		"99 04 11223344",                       // Unknown Tag inside
	)

	record, err := ParseDirectoryRecord(rawData)

	fmt.Printf("%v\n", record)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	report := record.Describe()
	actualLines := strings.Split(report, "\n")

	fmt.Println(report)

	expectedLines := []string{
		"=== EMV DIRECTORY RECORD ===",
		`    - Record.DDFName (9D): 54455354 ("TEST")`,
		`    - Record.Unknown Tag 99: DEAF`,
		`    - App[1].AID (4F): A0000000031010`,
	}

	if diff := cmp.Diff(expectedLines, actualLines); diff != "" {
		t.Errorf("Describe mismatch (-want +got):\n%s", diff)
	}
}
