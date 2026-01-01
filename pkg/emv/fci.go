package emv

import (
	"fmt"
	"strings"

	"github.com/gregLibert/smart-card/pkg/tlv"
	"github.com/moov-io/bertlv"
)

// FILE CONTROL INFORMATION (FCI) Logic according to EMV (Europay, Mastercard, Visa).

// FCI represents the EMV-specific File Control Information returned in response to a SELECT command.
type FCI struct {
	DFName              []byte                 `tlv:"84" fmt:"ascii"`
	ProprietaryTemplate FCIProprietaryTemplate `tlv:"A5"`
}

// FCIProprietaryTemplate contains the issuer-specific data found in tag 'A5'.
type FCIProprietaryTemplate struct {
	ApplicationLabel []byte `tlv:"50" fmt:"ascii"`

	// Optional EMV fields
	ApplicationPriorityIndicator []byte `tlv:"87" fmt:"int"`
	SFI                          []byte `tlv:"88"`
	PDOL                         []byte `tlv:"9F38"`
	LanguagePreference           []byte `tlv:"5F2D" fmt:"ascii"`
	IssuerCodeTableIndex         []byte `tlv:"9F11" fmt:"int"`
	ApplicationPreferredName     []byte `tlv:"9F12" fmt:"ascii"`

	IssuerDiscretionaryData *FCIIssuerDiscretionaryData `tlv:"BF0C"`

	Unknown []bertlv.TLV `tlv:",unknown"`
}

// FCIIssuerDiscretionaryData represents the discretionary data (Tag 'BF0C') which often contains specific bank or country information.
type FCIIssuerDiscretionaryData struct {
	LogEntry                           []byte `tlv:"9F4D"`
	IssuerIdentificationNumberExtended []byte `tlv:"9F0C"`
	IssuerCountryCodeAlpha3            []byte `tlv:"5F56" fmt:"ascii"`
	IssuerCountryCodeAlpha2            []byte `tlv:"5F55" fmt:"ascii"`
	BankIdentifierCode                 []byte `tlv:"5F54" fmt:"ascii"`
	IBAN                               []byte `tlv:"5F53" fmt:"ascii"`
	IssuerURL                          []byte `tlv:"5F50" fmt:"ascii"`
	IssuerIdentificationNumber         []byte `tlv:"42"`

	Unknown []bertlv.TLV `tlv:",unknown"`
}

// ParseFCI interprets raw byte data as an EMV FCI structure.
func ParseFCI(data []byte) (*FCI, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data cannot be parsed")
	}

	packets, err := bertlv.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("BER-TLV decode failed: %w", err)
	}

	var processingPackets []bertlv.TLV

	if len(packets) > 0 && strings.EqualFold(packets[0].Tag, "6F") {
		processingPackets = packets[0].TLVs
	} else {
		processingPackets = packets
	}

	fci := &FCI{}
	if err := tlv.UnmarshalFromPackets(processingPackets, fci); err != nil {
		return nil, fmt.Errorf("failed to map structure: %w", err)
	}

	return fci, nil
}

// Describe generates a detailed, standardized report of the FCI content.
func (f *FCI) Describe() string {
	var sb strings.Builder
	sb.WriteString("=== EMV FCI TEMPLATE ===")

	tlv.WriteStructFields(&sb, "FCI", f)

	tlv.WriteStructFields(&sb, "Proprietary", f.ProprietaryTemplate)

	if f.ProprietaryTemplate.IssuerDiscretionaryData != nil {
		tlv.WriteStructFields(&sb, "Discretionary", f.ProprietaryTemplate.IssuerDiscretionaryData)
	}

	return strings.TrimRight(sb.String(), "\n")
}
