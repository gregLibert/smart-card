package iso7816

import (
	"strings"
	"testing"

	"github.com/gregLibert/smart-card/pkg/tlv"
)

func TestSelectResult_Describe(t *testing.T) {
	cls, _ := NewClass(0x00)
	insSelect, _ := NewInstruction(INS_SELECT)
	aid := []byte("1PAY.SYS.DDF01")
	// P2=00 -> Return FCI | First
	cmdSelect := NewCommandAPDU(cls, insSelect, 0x04, 0x00, aid, 0)

	t.Run("Verify Exact Report Format", func(t *testing.T) {
		trace := Trace{
			{
				Command:  cmdSelect,
				Response: &ResponseAPDU{Status: NewStatusWord(0x61, 0x2B)},
			},
			{
				Command: NewCommandAPDU(cls, NewInstructionMust(INS_GET_RESPONSE), 0, 0, nil, 43),
				Response: &ResponseAPDU{
					Data: tlv.Hex(
						"6F 29",
						"84 0E 315041592E5359532E4444463031", // AID in FCP
						"A5 17",
						"8801015F2D046672656EBF0C0ABF0E07D2054C42503431",
					),
					Status: SW_NO_ERROR,
				},
			},
		}

		res, _ := NewSelectResult(trace)
		report := res.Describe()

		expectedLines := []string{
			"=== SELECT COMMAND REPORT ===",
			"[1] Command: SELECT FILE (Initial Request)",
			"    + Method:  04 -> Select by DF Name (AID)",
			"    + Control: 00 -> First/Only | Return FCI",
			`    + Data:    315041592E5359532E4444463031 ("1PAY.SYS.DDF01")`,
			"    + Result:  [61 2B] [OK] 2B (43) bytes still available",
			"",
			"[2] Protocol: Auto-handling (Sequence of 2 steps)",
			"    + Action:  Sending GET RESPONSE",
			"    + Result:  [9000] [OK] Final Status",
			"    + Payload: 43 bytes received",
			"      Dump:    6F29840E315041592E5359532E4444463031A5178801015F2D046672656EBF0C0ABF0E07D2054C42503431",
			"",
			"[=] FINAL OUTCOME:",
			"    - Structure: FCP + FMD",
			`    - FCP.DFName (84): 315041592E5359532E4444463031 ("1PAY.SYS.DDF01")`,
			"    - FCP.ProprietaryDataBER (A5): 8801015F2D046672656EBF0C0ABF0E07D2054C42503431",
			`    - FMD.ApplicationIdentifier (84): 315041592E5359532E4444463031 ("1PAY.SYS.DDF01")`,
		}

		for _, line := range expectedLines {
			if !strings.Contains(report, line) {
				t.Errorf("Report missing line: %q", line)
			}
		}
	})
}

func NewInstructionMust(code InsCode) Instruction {
	i, _ := NewInstruction(code)
	return i
}
