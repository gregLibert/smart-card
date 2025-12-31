package iso7816

import (
	"fmt"

	"github.com/gregLibert/smart-card/pkg/bits"
)

// Class Byte (CLA) Structure according to ISO/IEC 7816-4.
//
// The CLA byte conveys the command class, covering secure messaging (SM), command chaining,
// and logical channel selection.
//
// Structure:
// Bit 8: Proprietary (1) or Interindustry (0).
// Bit 7: Type of Interindustry (0=First, 1=Further).
// Bit 5: Command Chaining (0=Last/Only, 1=More follow).
//
// 1. First Interindustry Class (00xx xxxx):
//    - Bits 4-3: Secure Messaging (2 bits, 4 states).
//    - Bits 2-1: Logical Channel number (0-3).
//
// 2. Further Interindustry Class (01xx xxxx):
//    - Bit 6: Secure Messaging (1 bit: No SM or SM active).
//    - Bits 4-1: Logical Channel number minus 4 (encoding 0-15 for channels 4-19).

// SecureMessaging defines the security level applied to the APDU.
type SecureMessaging int

const (
	// SMNone indicates no secure messaging or no indication given.
	SMNone SecureMessaging = 0
	// SMProprietary indicates a proprietary secure messaging format (First Interindustry only).
	SMProprietary SecureMessaging = 1
	// SMHeaderNoProc indicates SM according to ISO, where the header is not processed.
	SMHeaderNoProc SecureMessaging = 2
	// SMHeaderAuth indicates SM according to ISO, where the header is authenticated (First Interindustry only).
	SMHeaderAuth SecureMessaging = 3
)

// Class represents the parsed ISO 7816-4 Class byte (CLA).
type Class struct {
	Raw             byte
	IsProprietary   bool
	IsChained       bool
	SecureMessaging SecureMessaging
	Channel         uint8 // Logical channel number (0-19)
}

// NewClass creates a Class object by decoding a raw CLA byte.
func NewClass(cla byte) (Class, error) {
	if cla == 0xFF {
		return Class{}, fmt.Errorf("invalid CLA value: 0xFF is reserved")
	}

	c := Class{Raw: cla}

	// Bit 8 indicates proprietary class
	if bits.IsSet(cla, 8) {
		c.IsProprietary = true
		return c, nil
	}

	// Bit 5 is always Command Chaining
	c.IsChained = bits.IsSet(cla, 5)

	// Bit 7 determines the encoding structure
	if !bits.IsSet(cla, 7) {
		// First Interindustry Structure (00xx xxxx)
		// SM is on bits 4-3
		c.SecureMessaging = SecureMessaging(bits.GetRange(cla, 4, 3))
		// Channel is on bits 2-1
		c.Channel = bits.GetRange(cla, 2, 1)
	} else {
		// Further Interindustry Structure (01xx xxxx)
		// SM is on bit 6
		if bits.IsSet(cla, 6) {
			c.SecureMessaging = SMHeaderNoProc
		} else {
			c.SecureMessaging = SMNone
		}
		// Channel offset is on bits 4-1 (Value + 4)
		c.Channel = bits.GetRange(cla, 4, 1) + 4
	}

	return c, nil
}

// NewInterindustryClass creates a Class object from parameters.
// It automatically selects First or Further interindustry encoding based on the channel number.
func NewInterindustryClass(isChained bool, sm SecureMessaging, channel uint8) (Class, error) {
	if channel > 19 {
		return Class{}, fmt.Errorf("channel %d out of range (max 19)", channel)
	}

	// Further Interindustry (Ch 4-19) only supports 1 bit for SM (No SM vs ISO SM)
	if channel >= 4 && (sm == SMProprietary || sm == SMHeaderAuth) {
		return Class{}, fmt.Errorf("SM indicator %d not supported for further interindustry range (ch 4-19)", sm)
	}

	c := Class{
		IsProprietary:   false,
		IsChained:       isChained,
		SecureMessaging: sm,
		Channel:         channel,
	}

	// Recompute the Raw byte to ensure consistency
	raw, err := c.Encode()
	if err != nil {
		return Class{}, err
	}
	c.Raw = raw

	return c, nil
}

// Encode converts the Class object back to its byte representation.
func (c *Class) Encode() (byte, error) {
	if c.IsProprietary {
		return c.Raw, nil
	}

	var res byte

	if c.Channel <= 3 {
		// First Interindustry Encoding
		if c.IsChained {
			res = bits.Set(res, 5)
		}
		// Set SM (Bits 4-3)
		res |= byte(c.SecureMessaging) << 2
		// Set Channel (Bits 2-1)
		res |= c.Channel
	} else {
		// Further Interindustry Encoding
		res = bits.Set(res, 7) // Indicator for Further Interindustry

		if c.IsChained {
			res = bits.Set(res, 5)
		}
		// SM (Bit 6)
		if c.SecureMessaging != SMNone {
			res = bits.Set(res, 6)
		}
		// Set Channel (Bits 4-1, Offset 4)
		res |= (c.Channel - 4)
	}

	return res, nil
}

// Verbose returns a human-readable description of the CLA byte configuration.
func (c Class) Verbose() string {
	if c.IsProprietary {
		return fmt.Sprintf("Class: Proprietary (0x%02X)", c.Raw)
	}

	rangeName := "First Interindustry (Ch 0-3)"
	if c.Channel >= 4 {
		rangeName = "Further Interindustry (Ch 4-19)"
	}

	smDesc := "Unknown"
	switch c.SecureMessaging {
	case SMNone:
		smDesc = "None"
	case SMProprietary:
		smDesc = "Proprietary"
	case SMHeaderNoProc:
		smDesc = "ISO (Header not processed)"
	case SMHeaderAuth:
		smDesc = "ISO (Header authenticated)"
	}

	chaining := "Last or only command"
	if c.IsChained {
		chaining = "More commands follow (Chaining)"
	}

	return fmt.Sprintf(
		"Range: %s\nChaining: %s\nSecure Messaging: %s\nLogical Channel: %d",
		rangeName, chaining, smDesc, c.Channel,
	)
}
