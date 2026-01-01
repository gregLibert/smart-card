package iso7816

import (
	"fmt"
	"strings"

	"github.com/gregLibert/smart-card/pkg/tlv"
)

// ReadRecordResult represents the outcome of a READ RECORD command execution.
type ReadRecordResult struct {
	Trace
}

func NewReadRecordResult(t Trace) (*ReadRecordResult, error) {
	if len(t) == 0 {
		return nil, fmt.Errorf("cannot create result from empty trace")
	}

	if t[0].Command.Instruction.Raw != INS_READ_RECORD {
		return nil, fmt.Errorf("trace must start with READ RECORD command (got %02X)", t[0].Command.Instruction.Raw)
	}

	return &ReadRecordResult{Trace: t}, nil
}

// Describe generates a detailed, ASCII-formatted report of the read operation.
func (r *ReadRecordResult) Describe() string {
	var sb strings.Builder

	sb.WriteString("=== READ RECORD COMMAND REPORT ===\n")

	tx0 := r.Trace[0]
	cmd := tx0.Command

	// Decode P2
	sfi := cmd.P2 >> 3
	mode := ReadRecordMode(cmd.P2 & 0x07)

	sb.WriteString("[1] Command: READ RECORD\n")

	targetStr := "Current EF"
	if sfi > 0 {
		targetStr = fmt.Sprintf("SFI %02X (%d)", sfi, sfi)
	}
	sb.WriteString(fmt.Sprintf("    + Target:  %s\n", targetStr))

	// Decode P1
	p1Desc := "Unknown"
	if (mode & 0b100) != 0 {
		if cmd.P1 == 0 {
			p1Desc = "Current Record"
		} else {
			p1Desc = fmt.Sprintf("Record Number %d", cmd.P1)
		}
	} else {
		p1Desc = fmt.Sprintf("Record Identifier %02X", cmd.P1)
	}

	sb.WriteString(fmt.Sprintf("    + P1:      %02X -> %s\n", cmd.P1, p1Desc))
	sb.WriteString(fmt.Sprintf("    + Mode:    %02X -> %s\n", byte(mode), mode))

	swVal := uint16(tx0.Response.Status)
	sw1 := byte(swVal >> 8)
	sw2 := byte(swVal)
	swHex := fmt.Sprintf("%02X %02X", sw1, sw2)

	resultMsg := "[OK]"
	resultDesc := "SW_NO_ERROR"

	if sw1 == 0x61 {
		resultDesc = fmt.Sprintf("%02X (%d) bytes still available", sw2, sw2)
	} else if sw1 == 0x6C {
		resultMsg = "[!!]"
		resultDesc = fmt.Sprintf("Wrong length, correct is %02X (%d)", sw2, sw2)
	} else if swVal != 0x9000 {
		resultMsg = "[!!]"
		resultDesc = tx0.Response.Status.Verbose()
	}

	sb.WriteString(fmt.Sprintf("    + Result:  [%s] %s %s\n", swHex, resultMsg, resultDesc))
	sb.WriteString("\n")

	lastTx := r.Last()
	finalPayload := lastTx.Response.Data

	if len(r.Trace) > 1 {
		sb.WriteString(fmt.Sprintf("[2] Protocol: Auto-handling (%d steps)\n", len(r.Trace)))
		sb.WriteString(fmt.Sprintf("    + Final SW: [%04X]\n", uint16(lastTx.Response.Status)))
	}

	sb.WriteString("[=] DATA OUTCOME:\n")
	if len(finalPayload) > 0 {
		sb.WriteString(fmt.Sprintf("    + Length: %d bytes\n", len(finalPayload)))
		sb.WriteString(fmt.Sprintf("    + Dump:   %X\n", finalPayload))
		sb.WriteString(fmt.Sprintf("    + ASCII:  %q\n", tlv.MakeSafeASCII(finalPayload)))
	} else {
		sb.WriteString("    - No Data Received.\n")
	}

	return strings.TrimRight(sb.String(), "\n")
}
