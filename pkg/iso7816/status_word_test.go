package iso7816

import (
	"strings"
	"testing"
)

func TestStatusWord_Triggering(t *testing.T) {
	tests := []struct {
		sw     StatusWord
		isTrig bool
	}{
		{NewStatusWord(0x62, 0x02), true},  // Lower bound
		{NewStatusWord(0x62, 0x80), true},  // Upper bound
		{NewStatusWord(0x64, 0x10), true},  // Error triggering
		{NewStatusWord(0x62, 0x01), false}, // Invalid (< 02)
		{NewStatusWord(0x62, 0x81), false}, // Invalid (> 80)
	}

	for _, tt := range tests {
		if got := tt.sw.IsTriggeringByCard(); got != tt.isTrig {
			t.Errorf("SW %X IsTriggeringByCard = %v, want %v", uint16(tt.sw), got, tt.isTrig)
		}
	}
}

func TestStatusWord_Counter(t *testing.T) {
	tests := []struct {
		sw        StatusWord
		isCounter bool
	}{
		{NewStatusWord(0x63, 0xC0), true},  // Counter 0
		{NewStatusWord(0x63, 0xCF), true},  // Counter 15
		{NewStatusWord(0x63, 0x00), false}, // Not a counter
		{NewStatusWord(0x63, 0x81), false}, // File filled
	}

	for _, tt := range tests {
		if got := tt.sw.IsCounter(); got != tt.isCounter {
			t.Errorf("SW %X IsCounter = %v, want %v", uint16(tt.sw), got, tt.isCounter)
		}
	}
}

func TestStatusWord_Classification(t *testing.T) {
	tests := []struct {
		sw        StatusWord
		isSuccess bool
		isWarning bool
		isError   bool
	}{
		{SW_NO_ERROR, true, false, false},
		{NewStatusWord(0x61, 0x10), true, false, false}, // Bytes Available
		{SW_WARN_EOF_REACHED, false, true, false},
		{NewStatusWord(0x63, 0xC2), false, true, false}, // Counter
		{SW_ERR_WRONG_LENGTH, false, false, true},
		{SW_ERR_FILE_NOT_FOUND, false, false, true},
	}

	for _, tt := range tests {
		if got := tt.sw.IsSuccess(); got != tt.isSuccess {
			t.Errorf("SW %X IsSuccess = %v, want %v", tt.sw, got, tt.isSuccess)
		}
		if got := tt.sw.IsWarning(); got != tt.isWarning {
			t.Errorf("SW %X IsWarning = %v, want %v", tt.sw, got, tt.isWarning)
		}
		if got := tt.sw.IsError(); got != tt.isError {
			t.Errorf("SW %X IsError = %v, want %v", tt.sw, got, tt.isError)
		}
	}
}

func TestStatusWord_Verbose(t *testing.T) {
	tests := []struct {
		sw       StatusWord
		contains string
	}{
		{NewStatusWord(0x62, 0x10), "Card expects query of 16 bytes"},
		{NewStatusWord(0x63, 0xC3), "counter = 3"},
		{NewStatusWord(0x61, 0x20), "32 bytes available"},
		{NewStatusWord(0x6C, 0x05), "correct Le is 5"},
		{SW_WARN_TRIGGERING_BY_CARD, "Card expects query of 2 bytes"},
		{SW_ERR_FILE_NOT_FOUND, "SW_ERR_FILE_NOT_FOUND"}, // Should use stringer
	}

	for _, tt := range tests {
		got := tt.sw.Verbose()
		if !strings.Contains(got, tt.contains) {
			t.Errorf("Verbose(%X) = %q; want containing %q", tt.sw, got, tt.contains)
		}
	}
}
