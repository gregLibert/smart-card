package iso7816

import (
	"fmt"

	"github.com/gregLibert/smart-card/pkg/bits"
)

// Instruction Byte (INS) Logic according to ISO/IEC 7816-4.
//
// The INS byte identifies the specific command command to be performed by the card.
//
// 1. Data Encoding (Bit 1):
//    When using the interindustry class, the least significant bit (Bit 1) often indicates
//    the format of the data field.
//    - 0: Standard or no specific formatting.
//    - 1: BER-TLV encoded data structure.
//    Example: READ BINARY (0xB0) vs READ BINARY (BER-TLV) (0xB1).
//
// 2. Reserved Ranges:
//    INS values where the upper nibble is '6' or '9' (0x6X or 0x9X) are invalid.
//    These values are reserved for Status Words (SW1) or transport layer control
//    procedures (ISO/IEC 7816-3).

//go:generate stringer -type=InsCode -output=instruction_string.go

// InsCode is a typed representation of the instruction byte.
type InsCode byte

// Standard Instruction (INS) codes as defined in ISO/IEC 7816-4.
const (
	INS_DEACTIVATE_FILE              InsCode = 0x04
	INS_ERASE_RECORD                 InsCode = 0x0C
	INS_ERASE_BINARY                 InsCode = 0x0E
	INS_ERASE_BINARY_BER             InsCode = 0x0F
	INS_PERFORM_SCQL_OPERATION       InsCode = 0x10
	INS_PERFORM_TRANSACTION_OPER     InsCode = 0x12
	INS_PERFORM_USER_OPERATION       InsCode = 0x14
	INS_VERIFY                       InsCode = 0x20
	INS_VERIFY_BER                   InsCode = 0x21
	INS_MANAGE_SECURITY_ENVIRONMENT  InsCode = 0x22
	INS_CHANGE_REFERENCE_DATA        InsCode = 0x24
	INS_DISABLE_VERIF_REQ            InsCode = 0x26
	INS_ENABLE_VERIF_REQ             InsCode = 0x28
	INS_PERFORM_SECURITY_OPERATION   InsCode = 0x2A
	INS_RESET_RETRY_COUNTER          InsCode = 0x2C
	INS_ACTIVATE_FILE                InsCode = 0x44
	INS_GENERATE_ASYMMETRIC_KEY_PAIR InsCode = 0x46
	INS_MANAGE_CHANNEL               InsCode = 0x70
	INS_EXTERNAL_AUTHENTICATE        InsCode = 0x82
	INS_GET_CHALLENGE                InsCode = 0x84
	INS_GENERAL_AUTHENTICATE         InsCode = 0x86
	INS_GENERAL_AUTHENTICATE_BER     InsCode = 0x87
	INS_INTERNAL_AUTHENTICATE        InsCode = 0x88
	INS_SEARCH_BINARY                InsCode = 0xA0
	INS_SEARCH_BINARY_BER            InsCode = 0xA1
	INS_SEARCH_RECORD                InsCode = 0xA2
	INS_SELECT                       InsCode = 0xA4
	INS_READ_BINARY                  InsCode = 0xB0
	INS_READ_BINARY_BER              InsCode = 0xB1
	INS_READ_RECORD                  InsCode = 0xB2
	INS_READ_RECORD_BER              InsCode = 0xB3
	INS_GET_RESPONSE                 InsCode = 0xC0
	INS_ENVELOPE                     InsCode = 0xC2
	INS_ENVELOPE_BER                 InsCode = 0xC3
	INS_GET_DATA                     InsCode = 0xCA
	INS_GET_DATA_BER                 InsCode = 0xCB
	INS_WRITE_BINARY                 InsCode = 0xD0
	INS_WRITE_BINARY_BER             InsCode = 0xD1
	INS_WRITE_RECORD                 InsCode = 0xD2
	INS_UPDATE_BINARY                InsCode = 0xD6
	INS_UPDATE_BINARY_BER            InsCode = 0xD7
	INS_PUT_DATA                     InsCode = 0xDA
	INS_PUT_DATA_BER                 InsCode = 0xDB
	INS_UPDATE_RECORD                InsCode = 0xDC
	INS_UPDATE_RECORD_BER            InsCode = 0xDD
	INS_CREATE_FILE                  InsCode = 0xE0
	INS_APPEND_RECORD                InsCode = 0xE2
	INS_DELETE_FILE                  InsCode = 0xE4
	INS_TERMINATE_DF                 InsCode = 0xE6
	INS_TERMINATE_EF                 InsCode = 0xE8
	INS_TERMINATE_CARD_USAGE         InsCode = 0xFE
)

// Instruction represents the parsed ISO 7816-4 Instruction byte (INS).
type Instruction struct {
	Raw      InsCode
	IsBERTLV bool
}

// NewInstruction creates an Instruction object with validation.
// It rejects '6X' and '9X' values as they are invalid according to ISO 7816-3.
func NewInstruction(ins InsCode) (Instruction, error) {
	// Validation: values starting with '6' or '9' are invalid for INS.
	highNibble := byte(ins) & 0xF0
	if highNibble == 0x60 || highNibble == 0x90 {
		return Instruction{}, fmt.Errorf("invalid INS 0x%02X: 6X and 9X are reserved", ins)
	}

	return Instruction{
		Raw:      ins,
		IsBERTLV: bits.IsSet(byte(ins), 1), // Bit 1 indicates BER-TLV preference
	}, nil
}

// Verbose returns a human-readable description of the instruction.
func (i Instruction) Verbose() string {
	format := "Standard"
	if i.IsBERTLV {
		format = "BER-TLV"
	}
	return fmt.Sprintf("INS: 0x%02X | Command: %s | Format: %s", byte(i.Raw), i.Raw.String(), format)
}
