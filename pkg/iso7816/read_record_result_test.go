package iso7816

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestReadRecordResult_Describe(t *testing.T) {
	cmd := ReadRecord(Class{}, 1, 1)
	resp := ResponseAPDU{
		Data:   []byte("HELLO"),
		Status: SW_NO_ERROR, // 9000
	}

	trace := Trace{
		{Command: cmd, Response: &resp},
	}

	res, err := NewReadRecordResult(trace)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	report := res.Describe()
	actualLines := strings.Split(report, "\n")

	expectedLines := []string{
		"=== READ RECORD COMMAND REPORT ===",
		"[1] Command: READ RECORD",
		"    + Target:  SFI 01 (1)",
		"    + P1:      01 -> Record Number 1",
		"    + Mode:    04 -> Ref Num: Read Record P1",
		"    + Result:  [90 00] [OK] SW_NO_ERROR",
		"",
		"[=] DATA OUTCOME:",
		"    + Length: 5 bytes",
		"    + Dump:   48454C4C4F",
		`    + ASCII:  "HELLO"`,
	}

	if diff := cmp.Diff(expectedLines, actualLines); diff != "" {
		t.Errorf("Report mismatch (-want +got):\n%s", diff)
	}
}

func TestReadRecordResult_Describe_Complex(t *testing.T) {
	cmd := NewReadRecordCommand(Class{}, 2, 0xFE, RefByID_NextOccurrence)

	resp := ResponseAPDU{
		Data:   nil,
		Status: 0x6A83, // Record not found
	}

	trace := Trace{
		{Command: cmd, Response: &resp},
	}

	res, _ := NewReadRecordResult(trace)
	report := res.Describe()
	actualLines := strings.Split(report, "\n")

	expectedLines := []string{
		"=== READ RECORD COMMAND REPORT ===",
		"[1] Command: READ RECORD",
		"    + Target:  SFI 02 (2)",
		"    + P1:      FE -> Record Identifier FE",
		"    + Mode:    02 -> Ref ID: Next Occurrence",
		"    + Result:  [6A 83] [!!] [6A83] SW_ERR_RECORD_NOT_FOUND",
		"",
		"[=] DATA OUTCOME:",
		"    - No Data Received.",
	}

	if diff := cmp.Diff(expectedLines, actualLines); diff != "" {
		t.Errorf("Report mismatch (-want +got):\n%s", diff)
	}
}
