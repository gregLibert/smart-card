package iso7816

import (
	"testing"
)

func TestNewClass(t *testing.T) {
	tests := []struct {
		name    string
		cla     byte
		wantErr bool
		check   func(Class) bool
	}{
		{
			name:    "Reserved FF",
			cla:     0xFF,
			wantErr: true,
		},
		{
			name: "First Interindustry - Ch 0, No SM",
			// 0b0(Prop)_0(First)_00(NoSM)_0(NoChain)_00(Ch0)
			cla: 0b0_0_00_0_00,
			check: func(c Class) bool {
				return !c.IsProprietary && c.Channel == 0 && c.SecureMessaging == SMNone
			},
		},
		{
			name: "First Interindustry - Ch 3, Chaining, SM Auth",
			// 0b0(Prop)_0(First)_11(SMAuth)_1(Chain)_11(Ch3)
			cla: 0b0_0_11_1_11,
			check: func(c Class) bool {
				return c.IsChained && c.Channel == 3 && c.SecureMessaging == SMHeaderAuth
			},
		},
		{
			name: "Further Interindustry - Ch 4, No SM",
			// 0b0(Prop)_1(Further)_0(NoSM)_0(NoChain)_0000(Offset 0 -> Ch 4)
			cla: 0b0_1_0_0_0000,
			check: func(c Class) bool {
				return !c.IsProprietary && c.Channel == 4 && c.SecureMessaging == SMNone
			},
		},
		{
			name: "Further Interindustry - Ch 19, SM, Chaining",
			// 0b0(Prop)_1(Further)_1(SM)_1(Chain)_1111(Offset 15 -> Ch 19)
			cla: 0b0_1_1_1_1111,
			check: func(c Class) bool {
				return c.IsChained && c.Channel == 19 && c.SecureMessaging == SMHeaderNoProc
			},
		},
		{
			name: "Proprietary Class",
			// 0b1(Prop)_0000000
			cla: 0b1_0000000,
			check: func(c Class) bool {
				return c.IsProprietary
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClass(tt.cla)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClass() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !tt.check(c) {
				t.Errorf("NewClass(%08b) failed validation: %+v", tt.cla, c)
			}
		})
	}
}

func TestNewInterindustryClass_Validation(t *testing.T) {
	t.Run("Unsupported SM for Further Interindustry", func(t *testing.T) {
		_, err := NewInterindustryClass(false, SMHeaderAuth, 5)
		if err == nil {
			t.Error("Should have failed: SMHeaderAuth is not supported for channels 4-19")
		}
	})

	t.Run("Channel Out of Range", func(t *testing.T) {
		_, err := NewInterindustryClass(false, SMNone, 20)
		if err == nil {
			t.Error("Should have failed: channel 20 is out of range")
		}
	})

	t.Run("Valid Construction", func(t *testing.T) {
		c, err := NewInterindustryClass(true, SMHeaderNoProc, 10)
		if err != nil {
			t.Fatalf("Should have succeeded, got error: %v", err)
		}
		if c.Channel != 10 || !c.IsChained {
			t.Errorf("Class fields mismatch: %+v", c)
		}
		// 10 = 4 + 6 (0110).
		// Expect: 0(Prop)_1(Further)_1(SM)_1(Chain)_0110(Offset 6) -> 0x76
		expected := byte(0b0_1_1_1_0110)
		if c.Raw != expected {
			t.Errorf("Computed Raw byte invalid: got %08b, want %08b", c.Raw, expected)
		}
	})
}

func TestClass_Encode_RoundTrip(t *testing.T) {
	testCases := []byte{
		0b0_0_00_0_00,  // First Interindustry: Ch 0, No SM, Last Command
		0b0_0_11_1_11,  // First Interindustry: Ch 3, SM Auth, Chaining
		0b0_1_0_0_0000, // Further Interindustry: Ch 4, No SM, Last Command
		0b0_1_1_1_1111, // Further Interindustry: Ch 19, SM ISO, Chaining
	}

	for _, originalCla := range testCases {
		c, err := NewClass(originalCla)
		if err != nil {
			t.Fatalf("Failed to create class from %08b: %v", originalCla, err)
		}

		encoded, err := c.Encode()
		if err != nil {
			t.Fatalf("Failed to encode class %v: %v", c, err)
		}

		if encoded != originalCla {
			t.Errorf("Round-trip mismatch: got %08b, want %08b", encoded, originalCla)
		}
	}
}
