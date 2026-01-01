package iso7816

import (
	"fmt"
)

// READ RECORD COMMAND LOGIC (ISO 7816-4):
// The READ RECORD command (INS 'B2') reads the content of one or more records
// from the current Elementary File (EF) or a specified SFI.
//
// P1 (Record Number or ID):
// - If P2 indicates "Record number" (Bits 3=1), P1 is the record number (00 = current).
// - If P2 indicates "Record identifier" (Bits 3=0), P1 is the record identifier.
//
// P2 (Reference Control):
// - Bits 8-4: Short File Identifier (SFI). If 0, use Current EF.
// - Bit 3:    0=Reference by ID, 1=Reference by Number.
// - Bits 2-1: Occurrence/Mode (First, Last, Next, Prev, or All).

// ReadRecordMode defines how to interpret P1 and which record(s) to read.
type ReadRecordMode byte

const (
	// P1 is Record IDENTIFIER (Bit 3 = 0)
	RefByID_FirstOccurrence    ReadRecordMode = 0b000
	RefByID_LastOccurrence     ReadRecordMode = 0b001
	RefByID_NextOccurrence     ReadRecordMode = 0b010
	RefByID_PreviousOccurrence ReadRecordMode = 0b011

	// P1 is Record NUMBER (Bit 3 = 1)
	RefByNum_ReadP1              ReadRecordMode = 0b100
	RefByNum_ReadAllFromP1       ReadRecordMode = 0b101
	RefByNum_ReadAllFromLastToP1 ReadRecordMode = 0b110
)

func (m ReadRecordMode) String() string {
	switch m {
	case RefByID_FirstOccurrence:
		return "Ref ID: First Occurrence"
	case RefByID_LastOccurrence:
		return "Ref ID: Last Occurrence"
	case RefByID_NextOccurrence:
		return "Ref ID: Next Occurrence"
	case RefByID_PreviousOccurrence:
		return "Ref ID: Previous Occurrence"
	case RefByNum_ReadP1:
		return "Ref Num: Read Record P1"
	case RefByNum_ReadAllFromP1:
		return "Ref Num: Read All from P1"
	case RefByNum_ReadAllFromLastToP1:
		return "Ref Num: Read All from Last to P1"
	default:
		return fmt.Sprintf("Unknown Mode (0x%X)", byte(m))
	}
}

// NewReadRecordCommand creates a raw READ RECORD command.
func NewReadRecordCommand(
	cla Class,
	sfi byte,
	p1 byte,
	mode ReadRecordMode,
) *CommandAPDU {
	// P2 Construction (Table 49): (SFI << 3) | Mode
	p2 := (sfi << 3) | byte(mode)

	ins, _ := NewInstruction(INS_READ_RECORD)

	// FIX: READ RECORD is a "Case 2" command (No data sent, Data expected).
	// We MUST request a response length. Using MaxShortLe (256) ensures
	// the encoder appends '00' at the end of the APDU.
	return NewCommandAPDU(cla, ins, p1, p2, nil, MaxShortLe)
}

// ReadRecord reads a specific record by its Number (Mode '100').
func ReadRecord(cla Class, sfi byte, recordNumber byte) *CommandAPDU {
	return NewReadRecordCommand(cla, sfi, recordNumber, RefByNum_ReadP1)
}

// ReadAllRecords reads all records starting from startRecordNumber (Mode '101').
func ReadAllRecords(cla Class, sfi byte, startRecordNumber byte) *CommandAPDU {
	return NewReadRecordCommand(cla, sfi, startRecordNumber, RefByNum_ReadAllFromP1)
}
