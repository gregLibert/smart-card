package iso7816

import (
	"fmt"
)

// SELECT COMMAND LOGIC (ISO 7816-4):
// The SELECT command (INS 'A4') opens a file (MF, DF, or EF) or an application.
//
// P1 (Selection Method):
// Indicates how the file is targeted (by ID, by Name/AID, by Path, etc.).
//
// P2 (Selection Control):
// Controls the response content and the file occurrence.
// - Bits 4-3: Response Type (FCI, FCP, FMD, or No Data).
// - Bits 2-1: Occurrence (First, Last, Next, Previous).

// SelectionMethod defines how the file is targeted (P1).
type SelectionMethod byte

const (
	SelectByFileID          SelectionMethod = 0x00
	SelectChildDF           SelectionMethod = 0x01
	SelectEFUnderCurrentDF  SelectionMethod = 0x02
	SelectParentDF          SelectionMethod = 0x03
	SelectByDFName          SelectionMethod = 0x04 // Select by AID
	SelectPathFromMF        SelectionMethod = 0x08
	SelectPathFromCurrentDF SelectionMethod = 0x09
)

func (s SelectionMethod) String() string {
	switch s {
	case SelectByFileID:
		return "Select by File ID"
	case SelectChildDF:
		return "Select Child DF"
	case SelectEFUnderCurrentDF:
		return "Select EF under current DF"
	case SelectParentDF:
		return "Select Parent DF"
	case SelectByDFName:
		return "Select by DF Name (AID)"
	case SelectPathFromMF:
		return "Select Path from MF"
	case SelectPathFromCurrentDF:
		return "Select Path from Current DF"
	default:
		return fmt.Sprintf("Unknown Method (0x%02X)", byte(s))
	}
}

// FileOccurrence defines which instance of the file to select (Bits 1-2 of P2).
type FileOccurrence byte

const (
	FirstOrOnlyOccurrence FileOccurrence = 0b0000_00_00
	LastOccurrence        FileOccurrence = 0b0000_00_01
	NextOccurrence        FileOccurrence = 0b0000_00_10
	PreviousOccurrence    FileOccurrence = 0b0000_00_11
)

func (f FileOccurrence) String() string {
	switch f {
	case FirstOrOnlyOccurrence:
		return "First/Only"
	case LastOccurrence:
		return "Last"
	case NextOccurrence:
		return "Next"
	case PreviousOccurrence:
		return "Previous"
	default:
		return "Unknown Occurrence"
	}
}

// SelectionControl defines what data to return (Bits 3-4 of P2).
type SelectionControl byte

const (
	ReturnFCI    SelectionControl = 0b0000_00_00
	ReturnFCP    SelectionControl = 0b0000_01_00
	ReturnFMD    SelectionControl = 0b0000_10_00
	ReturnNoData SelectionControl = 0b0000_11_00
)

func (s SelectionControl) String() string {
	switch s {
	case ReturnFCI:
		return "Return FCI"
	case ReturnFCP:
		return "Return FCP"
	case ReturnFMD:
		return "Return FMD"
	case ReturnNoData:
		return "No Response Data"
	default:
		return "Unknown Control"
	}
}

// NewSelectCommand creates a generic SELECT command.
func NewSelectCommand(
	cla Class,
	method SelectionMethod,
	occurrence FileOccurrence,
	ctrl SelectionControl,
	data []byte,
) *CommandAPDU {
	// P2 Construction: Combine Occurrence (bits 1-2) and Control Info (bits 3-4).
	p2 := byte(ctrl) | byte(occurrence)

	ins, _ := NewInstruction(INS_SELECT)

	// T=0 Protocol Compatibility:
	// - CASE 3 (Sending Data): We MUST set Le=0. We cannot send Lc and Le simultaneously.
	//   The card will respond with '61 XX' (Bytes available), and the Client handles it.
	// - CASE 2 (No Data): We can safely request MaxShortLe (256).
	ne := 0
	if len(data) == 0 && ctrl != ReturnNoData {
		ne = MaxShortLe
	}

	return NewCommandAPDU(cla, ins, byte(method), p2, data, ne)
}

// SelectByAID creates a simplified SELECT command to select an application by its name (AID).
func SelectByAID(cla Class, aid []byte) *CommandAPDU {
	return NewSelectCommand(
		cla,
		SelectByDFName,
		FirstOrOnlyOccurrence,
		ReturnFCI,
		aid,
	)
}

// SelectMF creates a command to select the Master File.
func SelectMF(cla Class) *CommandAPDU {
	return NewSelectCommand(
		cla,
		SelectByFileID,
		FirstOrOnlyOccurrence,
		ReturnFCI,
		nil,
	)
}
