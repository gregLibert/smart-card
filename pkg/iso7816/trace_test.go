package iso7816

import (
	"testing"
)

func makeTx(sw StatusWord) Transaction {
	return Transaction{
		Command:  &CommandAPDU{},
		Response: &ResponseAPDU{Status: sw},
	}
}

func TestTransaction_IsSuccess(t *testing.T) {
	tests := []struct {
		name string
		tx   Transaction
		want bool
	}{
		{
			name: "Successful Transaction (9000)",
			tx:   makeTx(SW_NO_ERROR),
			want: true,
		},
		{
			name: "Warning/Process Completed (6110)",
			tx:   makeTx(NewStatusWord(0x61, 0x10)),
			want: true, // 61xx is considered a success in IsSuccess() logic
		},
		{
			name: "Error Transaction (6A82)",
			tx:   makeTx(SW_ERR_FILE_NOT_FOUND),
			want: false,
		},
		{
			name: "Nil Response (Incomplete Transaction)",
			tx:   Transaction{Command: &CommandAPDU{}, Response: nil},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tx.IsSuccess(); got != tt.want {
				t.Errorf("Transaction.IsSuccess() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTrace_Logic(t *testing.T) {
	t.Run("Empty Trace", func(t *testing.T) {
		var tr Trace
		if tr.Last() != nil {
			t.Error("Empty trace Last() should be nil")
		}
		if tr.IsSuccess() {
			t.Error("Empty trace IsSuccess() should be false")
		}
	})

	t.Run("Single Transaction Trace", func(t *testing.T) {
		tr := Trace{makeTx(SW_NO_ERROR)}
		if tr.Last() == nil {
			t.Fatal("Last() should not be nil")
		}
		if !tr.IsSuccess() {
			t.Error("Should be successful")
		}
	})

	t.Run("Multi-Step Trace (Scenario: 61XX then 9000)", func(t *testing.T) {
		// Simulates:
		// 1. SELECT -> 61 10 (Response available)
		// 2. GET RESPONSE -> 90 00 (Success)
		tr := Trace{
			makeTx(NewStatusWord(0x61, 0x10)),
			makeTx(SW_NO_ERROR),
		}

		if tr.Last().Response.Status != SW_NO_ERROR {
			t.Errorf("Last transaction mismatch")
		}
		if !tr.IsSuccess() {
			t.Error("Trace should be successful if the last action succeeded")
		}
	})

	t.Run("Multi-Step Trace (Scenario: Failure at the end)", func(t *testing.T) {
		// Simulates a failure on the final step
		tr := Trace{
			makeTx(SW_NO_ERROR),           // Previous step ok
			makeTx(SW_ERR_FILE_NOT_FOUND), // Final step fails
		}

		if tr.IsSuccess() {
			t.Error("Trace should fail if the last action failed")
		}
	})
}
