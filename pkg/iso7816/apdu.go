package iso7816

import (
	"bytes"
	"fmt"
)

// APDU (Application Protocol Data Unit) structures and encodings according to ISO/IEC 7816-3 and 7816-4.
//
// COMMAND APDU (C-APDU):
// A command consists of a mandatory Header (4 bytes) and an optional Body.
//
// 1. Header:
//   - CLA (Class): Security, Chaining, Logical Channel.
//   - INS (Instruction): The specific command to execute.
//   - P1, P2 (Parameters): Command modifiers.
//
// 2. Body:
//   - Lc (Length Command): Number of bytes in the data field.
//   - Data: The command payload.
//   - Le (Length Expected): Maximum number of bytes expected in the response.
//
// ENCODING CASES (ISO 7816-3):
// - Case 1: No Data, No Response (Header only).
// - Case 2: No Data, Response Expected (Header + Le).
// - Case 3: Data Present, No Response (Header + Lc + Data).
// - Case 4: Data Present, Response Expected (Header + Lc + Data + Le).
//
// LENGTH MODES:
//   - Short Length: Lc/Le encoded on 1 byte (Max 255/256).
//   - Extended Length: Lc/Le encoded on multiple bytes (Max 65535/65536).
//     Extended mode is triggered if Lc > 255 or Le > 256.
//
// RESPONSE APDU (R-APDU):
// A response sent by the card consists of an optional Body and a mandatory Trailer.
//
// 1. Body (Data Field):
//   - Variable length sequence of bytes containing the response data.
//
// 2. Trailer (Status Word):
//   - SW1 (1 byte): Command processing status (High byte).
//   - SW2 (1 byte): Command processing qualification (Low byte).
//   - Example: 0x9000 indicates success.
//
// TRANSACTION:
// A logical exchange consisting of sending one Command APDU and receiving one Response APDU.

// APDU Limits and Constants according to ISO 7816-3.
const (
	// MaxShortLc is the maximum data length (Nc) encodable in Short Length mode (1 byte).
	MaxShortLc = 255

	// MaxShortLe is the maximum expected response length (Ne) encodable in Short Length mode.
	// In Short mode, 0x00 encodes 256.
	MaxShortLe = 256

	// MaxExtendedLc is the theoretical limit for Lc in Extended mode (16-bit unsigned).
	MaxExtendedLc = 65535

	// MaxExtendedLe is the maximum Ne encodable in Extended Length mode.
	// In Extended mode, 0x0000 encodes 65536.
	MaxExtendedLe = 65536

	// MaxAPDUBufferSize defines a safe buffer limit for Extended APDUs.
	// Calculation: Header(4) + ExtLc(3) + MaxData(65535) + ExtLe(2) + Safety Margin(1).
	MaxAPDUBufferSize = 4 + 3 + MaxExtendedLc + 2 + 1
)

// CommandAPDU represents a command sent to the card.
type CommandAPDU struct {
	Class       Class
	Instruction Instruction
	P1, P2      byte
	Data        []byte
	Ne          int // Expected response length (0 means none)
}

// NewCommandAPDU creates a basic command.
func NewCommandAPDU(cla Class, ins Instruction, p1, p2 byte, data []byte, ne int) *CommandAPDU {
	return &CommandAPDU{
		Class:       cla,
		Instruction: ins,
		P1:          p1,
		P2:          p2,
		Data:        data,
		Ne:          ne,
	}
}

// Bytes encodes the CommandAPDU into its byte representation (C-APDU).
// It automatically handles the selection between Short and Extended encoding
// based on the length of Data (Nc) and the expected response length (Ne).
func (c *CommandAPDU) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// 1. Encode Header
	class, err := c.Class.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode Class: %w", err)
	}
	buf.WriteByte(class)
	buf.WriteByte(byte(c.Instruction.Raw))
	buf.WriteByte(c.P1)
	buf.WriteByte(c.P2)

	nc := len(c.Data)
	ne := c.Ne

	// Determine encoding mode
	isExtended := nc > MaxShortLc || ne > MaxShortLe

	// 2. Encode Lc Field & Data Field
	if nc > 0 {
		if !isExtended {
			// Case 3/4 Short: Lc (1 byte) + Data
			buf.WriteByte(byte(nc))
		} else {
			// Case 3/4 Extended: 00 + Lc (2 bytes) + Data
			buf.WriteByte(0x00)
			buf.WriteByte(byte(nc >> 8))
			buf.WriteByte(byte(nc))
		}
		buf.Write(c.Data)
	}

	// 3. Encode Le Field
	if ne > 0 {
		if !isExtended {
			// Case 2/4 Short: Le (1 byte)
			if ne == MaxShortLe {
				buf.WriteByte(0x00) // 0x00 represents 256
			} else {
				buf.WriteByte(byte(ne))
			}
		} else {
			// Case 2/4 Extended
			// If Lc was absent (Case 2 Extended), we need a leading 00 to distinguish Le from Lc.
			if nc == 0 {
				buf.WriteByte(0x00)
			}

			if ne == MaxExtendedLe {
				// 0x0000 represents 65536
				buf.WriteByte(0x00)
				buf.WriteByte(0x00)
			} else {
				// Le (2 bytes Big Endian)
				buf.WriteByte(byte(ne >> 8))
				buf.WriteByte(byte(ne))
			}
		}
	}

	return buf.Bytes(), nil
}

// String returns a readable representation of the command meta-data.
func (c *CommandAPDU) String() string {
	return fmt.Sprintf("%s | P1: %02X, P2: %02X | Lc: %d | Le: %d",
		c.Instruction.Verbose(), c.P1, c.P2, len(c.Data), c.Ne)
}

// ResponseAPDU represents the reply from the card (R-APDU).
type ResponseAPDU struct {
	Data   []byte
	Status StatusWord
}

// ParseResponseAPDU parses raw bytes received from the card into a ResponseAPDU.
// The input must contain at least 2 bytes (SW1, SW2).
func ParseResponseAPDU(raw []byte) (*ResponseAPDU, error) {
	if len(raw) < 2 {
		return nil, fmt.Errorf("response too short: length %d", len(raw))
	}

	indexSW1 := len(raw) - 2
	data := raw[:indexSW1]
	sw1 := raw[indexSW1]
	sw2 := raw[indexSW1+1]

	return &ResponseAPDU{
		Data:   data,
		Status: NewStatusWord(sw1, sw2),
	}, nil
}

// String returns a readable representation of the response.
func (r *ResponseAPDU) String() string {
	return fmt.Sprintf("Data (%d bytes) | Status: %s", len(r.Data), r.Status.Verbose())
}

// Transaction represents a completed Command-Response pair.
type Transaction struct {
	Command  *CommandAPDU
	Response *ResponseAPDU
}

// IsSuccess checks if the transaction ended with a successful status.
func (t *Transaction) IsSuccess() bool {
	if t.Response == nil {
		return false
	}
	return t.Response.Status.IsSuccess()
}
