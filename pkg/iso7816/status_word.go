package iso7816

import (
	"fmt"

	"github.com/gregLibert/smart-card/pkg/bits"
)

// Dynamic Status Word Logic:
//
// While most Status Words (SW) are static 2-byte values (e.g., 0x9000), ISO 7816-4 defines
// specific ranges where the value is dynamic and carries contextual information:
//
// 1. '61XX' (SW1=0x61): Process Completed, Response Available.
//    XX indicates the number of extra bytes available for retrieval (GET RESPONSE).
//
// 2. '6CXX' (SW1=0x6C): Wrong Length.
//    XX indicates the correct expected length (Le) for the command.
//
// 3. '62XX' and '64XX' (Warning/Execution Error): Triggering by the Card.
//    If XX is in range [0x02, 0x80], the card requests a specific action or indicates
//    data issues. XX represents the number of bytes involved.
//
// 4. '63CX' (Warning): Counter Management.
//    If the upper nibble of SW2 is 'C' (0xC0-0xCF), the lower nibble represents
//    a counter value (e.g., remaining PIN retries).

//go:generate stringer -type=StatusWord -output=status_word_string.go

// StatusWord represents the two-byte status response (SW1-SW2) returned by the smart card.
type StatusWord uint16

// NewStatusWord creates a StatusWord instance from two separate bytes.
func NewStatusWord(sw1, sw2 byte) StatusWord {
	return StatusWord(uint16(sw1)<<8 | uint16(sw2))
}

// SW1 returns the first byte (high byte) of the status word.
func (sw StatusWord) SW1() byte {
	return byte(sw >> 8)
}

// SW2 returns the second byte (low byte) of the status word.
func (sw StatusWord) SW2() byte {
	return byte(sw)
}

// IsTriggeringByCard checks if the status indicates a "Triggering by the card" event.
func (sw StatusWord) IsTriggeringByCard() bool {
	sw1 := sw.SW1()
	sw2 := sw.SW2()

	if sw2 < 0x02 || sw2 > 0x80 {
		return false
	}
	return sw1 == 0x62 || sw1 == 0x64
}

// IsCounter checks if the status indicates a non-volatile memory change counter.
func (sw StatusWord) IsCounter() bool {
	if sw.SW1() != 0x63 {
		return false
	}
	// Check if upper nibble of SW2 is 0xC
	return bits.GetRange(sw.SW2(), 8, 5) == 0x0C
}

// IsSuccess returns true if the command was processed successfully (9000) or
// if data is available (61XX).
func (sw StatusWord) IsSuccess() bool {
	return sw == SW_NO_ERROR || sw.SW1() == 0x61
}

// IsWarning returns true if the status indicates a warning (62XX or 63XX).
func (sw StatusWord) IsWarning() bool {
	sw1 := sw.SW1()
	return sw1 == 0x62 || sw1 == 0x63
}

// IsError returns true if the status indicates an execution error (64XX to 6FXX).
func (sw StatusWord) IsError() bool {
	sw1 := sw.SW1()
	return sw1 >= 0x64 && sw1 <= 0x6F
}

// Verbose returns a human-readable description of the status word.
// It prioritizes dynamic ISO definitions over static string generation.
func (sw StatusWord) Verbose() string {
	sw1 := sw.SW1()
	sw2 := sw.SW2()

	if sw.IsTriggeringByCard() {
		action := "Warning (Triggering)"
		if sw1 == 0x64 {
			action = "Error/Abort (Triggering)"
		}
		return fmt.Sprintf("%s: Card expects query of %d bytes", action, sw2)
	}

	if sw.IsCounter() {
		return fmt.Sprintf("Warning: State changed, counter = %d", bits.GetRange(sw2, 4, 1))
	}

	if sw1 == 0x61 {
		return fmt.Sprintf("Process completed, %d bytes available", sw2)
	}

	if sw1 == 0x6C {
		return fmt.Sprintf("Wrong length, correct Le is %d", sw2)
	}

	desc := sw.String()

	if len(desc) >= 11 && desc[:11] == "StatusWord(" {
		return fmt.Sprintf("[%04X] %s", uint16(sw), sw.genericCategoryDescription())
	}

	return fmt.Sprintf("[%04X] %s", uint16(sw), desc)
}

// genericCategoryDescription provides a fallback description based on SW1.
func (sw StatusWord) genericCategoryDescription() string {
	switch sw.SW1() {
	case 0x62:
		return "Warning: NV memory unchanged"
	case 0x63:
		return "Warning: NV memory changed"
	case 0x64:
		return "Execution Error: NV memory unchanged"
	case 0x65:
		return "Execution Error: NV memory changed"
	case 0x66:
		return "Execution Error: Security issue"
	case 0x68:
		return "Checking Error: Function not supported"
	case 0x69:
		return "Checking Error: Command not allowed"
	case 0x6A:
		return "Checking Error: Wrong parameters"
	default:
		return "Unknown Status"
	}
}

// Standard Status Word codes defined in ISO/IEC 7816-4.
const (
	SW_NO_ERROR StatusWord = 0x9000

	SW_WARN_NO_INFO              StatusWord = 0x6200
	SW_WARN_TRIGGERING_BY_CARD   StatusWord = 0x6202
	SW_WARN_DATA_CORRUPTED       StatusWord = 0x6281
	SW_WARN_EOF_REACHED          StatusWord = 0x6282
	SW_WARN_FILE_DEACTIVATED     StatusWord = 0x6283
	SW_WARN_FCI_BAD_FORMAT       StatusWord = 0x6284
	SW_WARN_TERMINATION_STATE    StatusWord = 0x6285
	SW_WARN_NO_INPUT_FROM_SENSOR StatusWord = 0x6286

	SW_WARN_NV_CHANGED_NO_INFO StatusWord = 0x6300
	SW_WARN_FILE_FILLED        StatusWord = 0x6381
	SW_WARN_COUNTER_0          StatusWord = 0x63C0

	SW_ERR_EXEC_NO_INFO            StatusWord = 0x6400
	SW_ERR_EXEC_IMMEDIATE_RESPONSE StatusWord = 0x6401
	SW_ERR_EXEC_TRIGGERING_BY_CARD StatusWord = 0x6402

	SW_ERR_NV_CHANGED_NO_INFO StatusWord = 0x6500
	SW_ERR_MEMORY_FAILURE     StatusWord = 0x6581
	SW_ERR_SECURITY_ISSUE     StatusWord = 0x6600

	SW_ERR_WRONG_LENGTH              StatusWord = 0x6700
	SW_ERR_CHECKING_NO_INFO          StatusWord = 0x6800
	SW_ERR_LOGICAL_CHANNEL_NOT_SUPP  StatusWord = 0x6881
	SW_ERR_SECURE_MESSAGING_NOT_SUPP StatusWord = 0x6882
	SW_ERR_LAST_COMMAND_EXPECTED     StatusWord = 0x6883
	SW_ERR_CHAINING_NOT_SUPP         StatusWord = 0x6884

	SW_ERR_CMD_NOT_ALLOWED_NO_INFO StatusWord = 0x6900
	SW_ERR_CMD_INCOMPATIBLE_FILE   StatusWord = 0x6981
	SW_ERR_SECURITY_STATUS_NOT_SAT StatusWord = 0x6982
	SW_ERR_AUTH_METHOD_BLOCKED     StatusWord = 0x6983
	SW_ERR_REF_DATA_NOT_USABLE     StatusWord = 0x6984
	SW_ERR_COND_OF_USE_NOT_SAT     StatusWord = 0x6985
	SW_ERR_CMD_NOT_ALLOWED_NO_EF   StatusWord = 0x6986
	SW_ERR_SM_OBJ_MISSING          StatusWord = 0x6987
	SW_ERR_SM_OBJ_INCORRECT        StatusWord = 0x6988

	SW_ERR_WRONG_PARAMS_NO_INFO   StatusWord = 0x6A00
	SW_ERR_INCORRECT_PARAMS_DATA  StatusWord = 0x6A80
	SW_ERR_FUNC_NOT_SUPPORTED     StatusWord = 0x6A81
	SW_ERR_FILE_NOT_FOUND         StatusWord = 0x6A82
	SW_ERR_RECORD_NOT_FOUND       StatusWord = 0x6A83
	SW_ERR_NOT_ENOUGH_MEMORY      StatusWord = 0x6A84
	SW_ERR_NC_INCONSISTENT_TLV    StatusWord = 0x6A85
	SW_ERR_INCORRECT_PARAMS_P1P2  StatusWord = 0x6A86
	SW_ERR_NC_INCONSISTENT_P1P2   StatusWord = 0x6A87
	SW_ERR_REF_DATA_NOT_FOUND     StatusWord = 0x6A88
	SW_ERR_FILE_ALREADY_EXISTS    StatusWord = 0x6A89
	SW_ERR_DF_NAME_ALREADY_EXISTS StatusWord = 0x6A8A

	SW_ERR_WRONG_P1P2        StatusWord = 0x6B00
	SW_ERR_INS_INVALID       StatusWord = 0x6D00
	SW_ERR_CLA_NOT_SUPPORTED StatusWord = 0x6E00
	SW_ERR_UNKNOWN           StatusWord = 0x6F00
)
