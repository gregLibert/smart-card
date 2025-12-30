package tlv

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/moov-io/bertlv"
)

// Mock custom unmarshaler
type customType struct {
	Val string
}

func (c *customType) UnmarshalTLV(data []byte) error {
	c.Val = "custom:" + hex.EncodeToString(data)
	return nil
}

type nestedStruct struct {
	Version []byte `tlv:"82"`
}

type testStruct struct {
	AID     []byte       `tlv:"84"`
	Label   string       `tlv:"50"`
	Details nestedStruct `tlv:"A5"`
	Custom  customType   `tlv:"9F02"`
	Other   []bertlv.TLV `tlv:",unknown"`
}

func tlvHex(parts ...string) []byte {
	fullHex := strings.Join(parts, "")
	data, err := hex.DecodeString(fullHex)
	if err != nil {
		panic(fmt.Sprintf("Invalid hex in test data: %s", fullHex))
	}
	return data
}

func TestUnmarshal(t *testing.T) {
	rawData := tlvHex(
		"84", "02", "1122", // AID
		"50", "03", "414243", // Label "ABC"
		"A5", "03", "8201FF", // Nested Details (Template A5, Tag 82)
		"9F02", "01", "AA", // Custom type (Tag 9F02)
		"DF01", "01", "BB", // Unknown tag
	)

	var result testStruct
	err := Unmarshal(rawData, &result)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	fmt.Printf("%v\n", result)

	// Assertions
	if hex.EncodeToString(result.AID) != "1122" {
		t.Errorf("Expected AID 1122, got %s", hex.EncodeToString(result.AID))
	}

	if result.Label != "414243" {
		t.Errorf("Expected Label 414243, got %s", result.Label)
	}

	if hex.EncodeToString(result.Details.Version) != "ff" {
		t.Errorf("Expected nested Version ff, got %s", hex.EncodeToString(result.Details.Version))
	}

	if result.Custom.Val != "custom:aa" {
		t.Errorf("Expected custom:aa, got %s", result.Custom.Val)
	}

	if len(result.Other) != 1 || strings.ToUpper(result.Other[0].Tag) != "DF01" {
		t.Errorf("Unknown tag DF01 not captured correctly")
	}
}

func TestGetValue(t *testing.T) {
	rawData := tlvHex(
		"84", "02", "1122", // AID
		"50", "03", "414243", // Label "ABC"
	)

	t.Run("Existing Tag", func(t *testing.T) {
		val, err := GetValue(rawData, 0x84)
		if err != nil {
			t.Errorf("GetValue failed: %v", err)
		}
		if hex.EncodeToString(val) != "1122" {
			t.Errorf("Expected 1122, got %x", val)
		}
	})

	t.Run("Missing Tag", func(t *testing.T) {
		_, err := GetValue(rawData, 0x99)
		if err == nil {
			t.Error("Expected error for missing tag, got nil")
		}
	})
}

func TestUnmarshalErrors(t *testing.T) {
	t.Run("Non-pointer target", func(t *testing.T) {
		err := Unmarshal([]byte{0x84, 0x00}, testStruct{})
		if err == nil || !strings.Contains(err.Error(), "pointer") {
			t.Errorf("Expected pointer error, got %v", err)
		}
	})
}
