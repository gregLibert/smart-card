package emv

import (
	"fmt"
	"strings"

	"github.com/gregLibert/smart-card/pkg/tlv"
	"github.com/moov-io/bertlv"
)

type DirectoryDiscretionaryTemplate struct {
	ApplicationSelectionRegisteredProprietaryData []byte `tlv:"9F0A"`
	IssuerCountryCodeAlpha3                       []byte `tlv:"5F56" fmt:"ascii"`
	IssuerCountryCodeAlpha2                       []byte `tlv:"5F55" fmt:"ascii"`
	BankIdentifierCode                            []byte `tlv:"5F54" fmt:"ascii"`
	IBAN                                          []byte `tlv:"5F53" fmt:"ascii"`
	IssuerURL                                     []byte `tlv:"5F50" fmt:"ascii"`
	IssuerIdentificationNumber                    []byte `tlv:"42"`
	IssuerIdentificationNumberExtended            []byte `tlv:"9F0C"`
	LogEntry                                      []byte `tlv:"9F4D"`

	Unknown []bertlv.TLV `tlv:",unknown"`
}

// ApplicationTemplate (Tag '61') represents an entry in the Payment System Directory.
// It contains the necessary information to select a specific application.
type ApplicationTemplate struct {
	AID                          []byte                         `tlv:"4F"`             // Mandatory
	ApplicationLabel             []byte                         `tlv:"50" fmt:"ascii"` // Mandatory
	ApplicationPriorityIndicator []byte                         `tlv:"87" fmt:"int"`
	DirectoryDiscretionaryData   DirectoryDiscretionaryTemplate `tlv:"73"`
	ApplicationPreferredName     []byte                         `tlv:"9F12" fmt:"ascii"`
	DDFName                      []byte                         `tlv:"9D" fmt:"ascii"`

	Unknown []bertlv.TLV `tlv:",unknown"`
}

// DirectoryRecord represents the content of a record read from the PSE SFI.
// It is wrapped in a Record Template (Tag '70').
type DirectoryRecord struct {
	// A record can technically contain multiple application templates
	Applications []ApplicationTemplate `tlv:"61"`

	Unknown []bertlv.TLV `tlv:",unknown"`
}

// ParseDirectoryRecord interprets raw bytes from a READ RECORD command as EMV directory data.
func ParseDirectoryRecord(data []byte) (*DirectoryRecord, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty record data")
	}

	packets, err := bertlv.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("BER-TLV decode failed: %w", err)
	}

	// The record must be wrapped in Tag '70'
	var processingPackets []bertlv.TLV
	if len(packets) > 0 && strings.EqualFold(packets[0].Tag, "70") {
		processingPackets = packets[0].TLVs
	} else {
		return nil, fmt.Errorf("missing mandatory Record Template (Tag 70)")
	}

	record := &DirectoryRecord{}
	if err := tlv.UnmarshalFromPackets(processingPackets, record); err != nil {
		return nil, fmt.Errorf("failed to map directory record: %w", err)
	}

	return record, nil
}

// Describe generates a report for all applications found in the record.
func (r *DirectoryRecord) Describe() string {
	var sb strings.Builder
	sb.WriteString("=== EMV DIRECTORY RECORD ===")

	tlv.WriteStructFields(&sb, "Record", r)

	for i, app := range r.Applications {
		prefix := fmt.Sprintf("App[%d]", i+1)
		tlv.WriteStructFields(&sb, prefix, app)

		tlv.WriteStructFields(&sb, prefix+".Discretionary", app.DirectoryDiscretionaryData)
	}

	return strings.TrimRight(sb.String(), "\n")
}
