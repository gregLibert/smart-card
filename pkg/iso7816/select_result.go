package iso7816

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"

	"github.com/moov-io/bertlv"
)

// SELECT RESULT ANALYSIS:
// This file provides a high-level wrapper to analyze the execution of a SELECT command.
// It abstracts the complexity of the trace (retries, Get Response) to provide
// direct access to the File Control Information (FCI) and human-readable reports.

// SelectResult represents the outcome of a SELECT command execution.
// It wraps the transaction trace to provide high-level parsing (FCI)
// and a formatted human-readable report (Describe).
type SelectResult struct {
	Trace
}

// NewSelectResult creates a SelectResult from a raw transaction trace.
// It validates that the trace is not empty and that the logical operation
// started with a SELECT command (INS 0xA4).
func NewSelectResult(t Trace) (*SelectResult, error) {
	if len(t) == 0 {
		return nil, fmt.Errorf("cannot create result from empty trace")
	}

	if t[0].Command.Instruction.Raw != INS_SELECT {
		return nil, fmt.Errorf("trace must start with SELECT command (got %02X)", t[0].Command.Instruction.Raw)
	}

	return &SelectResult{Trace: t}, nil
}

// FCI attempts to parse the File Control Information (FCI) from the transaction trace.
// It automatically locates the correct response data (handling GET RESPONSE sequences)
// and interprets it according to the P2 parameter of the initial SELECT command.
func (r *SelectResult) FCI() (*FileControlInfo, error) {
	if !r.IsSuccess() {
		return nil, fmt.Errorf("selection failed, cannot parse FCI")
	}

	lastTx := r.Last()
	if lastTx == nil || len(lastTx.Response.Data) == 0 {
		return nil, fmt.Errorf("no response data found")
	}

	initialP2 := r.Trace[0].Command.P2
	return ParseSelectData(lastTx.Response.Data, initialP2)
}

// Describe generates a detailed, ASCII-formatted report of the selection process.
// It breaks down the initial request, protocol auto-handling (like GET RESPONSE),
// and provides a field-by-field dump of the parsed FCI structures (FCP/FMD).
func (r *SelectResult) Describe() string {
	var sb strings.Builder

	sb.WriteString("=== SELECT COMMAND REPORT ===\n")

	tx0 := r.Trace[0]
	cmd := tx0.Command

	method := SelectionMethod(cmd.P1)
	occ := FileOccurrence(cmd.P2 & 0x03)
	ctrl := SelectionControl(cmd.P2 & 0x0C)

	sb.WriteString("[1] Command: SELECT FILE (Initial Request)\n")
	sb.WriteString(fmt.Sprintf("    + Method:  %02X -> %s\n", cmd.P1, method))
	sb.WriteString(fmt.Sprintf("    + Control: %02X -> %s | %s\n", cmd.P2, occ, ctrl))

	if len(cmd.Data) > 0 {
		sb.WriteString(fmt.Sprintf("    + Data:    %X (%q)\n", cmd.Data, makeSafeASCII(cmd.Data)))
	}

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

	if len(tx0.Response.Data) > 0 {
		sb.WriteString(fmt.Sprintf("    + Payload: %d bytes received directly\n", len(tx0.Response.Data)))
	}
	sb.WriteString("\n")

	finalPayload := tx0.Response.Data

	if len(r.Trace) > 1 {
		sb.WriteString(fmt.Sprintf("[2] Protocol: Auto-handling (Sequence of %d steps)\n", len(r.Trace)))

		lastTx := r.Last()
		finalPayload = lastTx.Response.Data
		finalSW := uint16(lastTx.Response.Status)

		opName := "Unknown"
		switch lastTx.Command.Instruction.Raw {
		case INS_GET_RESPONSE:
			opName = "GET RESPONSE"
		case INS_SELECT:
			opName = "RE-SELECT (Correction)"
		}

		sb.WriteString(fmt.Sprintf("    + Action:  Sending %s\n", opName))
		sb.WriteString(fmt.Sprintf("    + Result:  [%04X] [OK] Final Status\n", finalSW))

		if len(finalPayload) > 0 {
			sb.WriteString(fmt.Sprintf("    + Payload: %d bytes received\n", len(finalPayload)))
			sb.WriteString(fmt.Sprintf("      Dump:    %X\n", finalPayload))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("[=] FINAL OUTCOME:\n")

	fci, err := r.FCI()
	if err != nil {
		if len(finalPayload) > 0 {
			sb.WriteString(fmt.Sprintf("    - FCI Parsing Failed: %v\n", err))
		} else {
			sb.WriteString("    - No Data returned to parse.\n")
		}
		return sb.String()
	}

	structures := []string{}
	if fci.FCP != nil {
		structures = append(structures, "FCP")
	}
	if fci.FMD != nil {
		structures = append(structures, "FMD")
	}
	if len(fci.ProprietaryRawData) > 0 {
		structures = append(structures, "ProprietaryRaw")
	}

	strList := "None"
	if len(structures) > 0 {
		strList = strings.Join(structures, " + ")
	}
	sb.WriteString(fmt.Sprintf("    - Structure: %s\n", strList))

	if fci.FCP != nil {
		writeStructFields(&sb, "FCP", fci.FCP)
	}
	if fci.FMD != nil {
		writeStructFields(&sb, "FMD", fci.FMD)
	}
	if len(fci.ProprietaryRawData) > 0 {
		sb.WriteString(fmt.Sprintf("    - Proprietary:   %X\n", fci.ProprietaryRawData))
	}

	return sb.String()
}

func writeStructFields(sb *strings.Builder, prefix string, s interface{}) {
	val := reflect.ValueOf(s).Elem()
	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		if field.Kind() == reflect.Slice && field.Type().Elem().Kind() == reflect.Uint8 {
			if !field.IsNil() && field.Len() > 0 {
				bytesVal := field.Bytes()
				formatTag := fieldType.Tag.Get("fmt")
				tlvTag := fieldType.Tag.Get("tlv")

				name := fieldType.Name
				if tlvTag != "" {
					name = fmt.Sprintf("%s (%s)", name, tlvTag)
				}

				displayVal := ""
				switch formatTag {
				case "ascii":
					displayVal = fmt.Sprintf("%X (%q)", bytesVal, makeSafeASCII(bytesVal))
				case "int":
					var integer int
					for _, b := range bytesVal {
						integer = (integer << 8) | int(b)
					}
					displayVal = fmt.Sprintf("%X (Dec: %d)", bytesVal, integer)
				default:
					displayVal = strings.ToUpper(hex.EncodeToString(bytesVal))
				}
				sb.WriteString(fmt.Sprintf("    - %s.%s: %s\n", prefix, name, displayVal))
			}
		}

		if field.Type() == reflect.TypeOf([]bertlv.TLV{}) {
			if !field.IsNil() && field.Len() > 0 {
				tlvs := field.Interface().([]bertlv.TLV)
				for _, t := range tlvs {
					sb.WriteString(fmt.Sprintf("    - %s.Unknown Tag %s:           %X\n", prefix, t.Tag, t.Value))
				}
			}
		}
	}
}

func makeSafeASCII(data []byte) string {
	return strings.Map(func(r rune) rune {
		if r >= 32 && r <= 126 {
			return r
		}
		return '.'
	}, string(data))
}
