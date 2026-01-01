package iso7816

import (
	"fmt"
	"strings"

	"github.com/gregLibert/smart-card/pkg/bits"
	"github.com/gregLibert/smart-card/pkg/tlv"
	"github.com/moov-io/bertlv"
)

// FILE CONTROL INFORMATION (FCI) Logic according to ISO/IEC 7816-4.
//
// When a SELECT command is issued, the card returns data describing the selected file.
// The format of this data is controlled by the P2 parameter of the command.
//
// STRUCTURES:
// 1. FCI (File Control Information) - Tag '6F': A wrapper template.
// 2. FCP (File Control Parameters) - Tag '62': Technical attributes.
// 3. FMD (File Management Data) - Tag '64': Administrative data.
//
// P2 SELECTION CONTROL (Bits 4-3):
// - 00: Return FCI (Optional '6F' wrapper containing '62' and/or '64').
// - 01: Return FCP (Mandatory '62').
// - 10: Return FMD (Mandatory '64').
// - 11: No Data returned.

// FCPTemplate (File Control Parameters) - Tag '62'.
type FCPTemplate struct {
	DataSizeExcludingStruct []byte `tlv:"80" fmt:"int"`
	TotalFileSize           []byte `tlv:"81" fmt:"int"`
	FileDescriptor          []byte `tlv:"82"`
	FileIdentifier          []byte `tlv:"83"`
	DFName                  []byte `tlv:"84" fmt:"ascii"`
	ProprietaryInfoRaw      []byte `tlv:"85"`
	SecurityAttrProprietary []byte `tlv:"86"`
	ExtFileControlInfoID    []byte `tlv:"87"`
	ShortEFIdentifier       []byte `tlv:"88"`
	LifeCycleStatus         []byte `tlv:"8A"`
	SecAttrRefExpanded      []byte `tlv:"8B"`
	SecurityAttrCompact     []byte `tlv:"8C"`
	SecEnvTemplateID        []byte `tlv:"8D"`
	ChannelSecurityAttr     []byte `tlv:"8E"`
	SecAttrTemplateData     []byte `tlv:"A0"`
	SecAttrTemplateProp     []byte `tlv:"A1"`
	OneOrMorePairs          []byte `tlv:"A2"`
	ProprietaryDataBER      []byte `tlv:"A5"`
	SecurityAttrExpanded    []byte `tlv:"AB"`
	CryptoMechanismID       []byte `tlv:"AC"`

	Unknown []bertlv.TLV `tlv:",unknown"`
}

// FMDTemplate (File Management Data) - Tag '64'.
type FMDTemplate struct {
	ApplicationIdentifier []byte `tlv:"84" fmt:"ascii"`
	ApplicationLabel      []byte `tlv:"50" fmt:"ascii"`
	ProprietaryData53     []byte `tlv:"53"`
	ProprietaryData73     []byte `tlv:"73"`

	Unknown []bertlv.TLV `tlv:",unknown"`
}

// FileControlInfo represents the parsed result of a SELECT command.
type FileControlInfo struct {
	FCP *FCPTemplate
	FMD *FMDTemplate

	// Unknown contains TLV tags that did not match FCP or FMD definitions
	Unknown []bertlv.TLV // (only populated in "flat" FCI parsing mode).

	ProprietaryRawData []byte
}

// GetAID attempts to retrieve the Application ID (Tag 84).
func (fci *FileControlInfo) GetAID() []byte {
	if fci.FCP != nil && len(fci.FCP.DFName) > 0 {
		return fci.FCP.DFName
	}
	if fci.FMD != nil && len(fci.FMD.ApplicationIdentifier) > 0 {
		return fci.FMD.ApplicationIdentifier
	}
	return nil
}

// DFName returns the Dedicated File Name (Tag 84) from FCP.
func (fci *FileControlInfo) DFName() []byte {
	if fci.FCP != nil {
		return fci.FCP.DFName
	}
	return nil
}

// ApplicationLabel returns the Application Label (Tag 50) from FMD.
func (fci *FileControlInfo) ApplicationLabel() []byte {
	if fci.FMD != nil {
		return fci.FMD.ApplicationLabel
	}
	return nil
}

// ParseSelectData parses the data field from a SELECT response according to P2.
func ParseSelectData(data []byte, p2 byte) (*FileControlInfo, error) {
	if len(data) == 0 {
		return nil, nil
	}

	if data[0] >= 0xC0 {
		return &FileControlInfo{ProprietaryRawData: data}, nil
	}

	packets, err := bertlv.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("BER-TLV decode failed: %w", err)
	}

	fci := &FileControlInfo{
		FCP: &FCPTemplate{},
		FMD: &FMDTemplate{},
	}

	control := bits.GetRange(p2, 4, 3)

	switch control {
	case 1:
		return fci, handleMandatoryTemplate(packets, "62", fci.FCP)

	case 2:
		return fci, handleMandatoryTemplate(packets, "64", fci.FMD)

	case 0:

		workingPackets := packets

		for _, p := range packets {
			if strings.EqualFold(p.Tag, "6F") {
				workingPackets = p.TLVs
				break
			}
		}

		foundFCP := unmarshalIfTagExists(workingPackets, "62", fci.FCP)
		foundFMD := unmarshalIfTagExists(workingPackets, "64", fci.FMD)

		// If explicit templates were found, we are done (unknowns remain nested in FCP/FMD).
		// If NO explicit template is found, we assume a "flat" structure.
		if !foundFCP && !foundFMD {
			if err := tlv.UnmarshalFromPackets(workingPackets, fci.FCP); err != nil {
				return nil, fmt.Errorf("flat FCP unmarshal failed: %w", err)
			}

			remainingUnknowns := fci.FCP.Unknown
			fci.FCP.Unknown = nil

			if err := tlv.UnmarshalFromPackets(remainingUnknowns, fci.FMD); err != nil {
				return nil, fmt.Errorf("flat FMD unmarshal failed: %w", err)
			}

			finalUnknowns := fci.FMD.Unknown
			fci.FMD.Unknown = nil
			fci.Unknown = finalUnknowns
		}

		return fci, nil

	default:
		return nil, nil
	}
}

func handleMandatoryTemplate(packets []bertlv.TLV, requiredTag string, target interface{}) error {
	if found := unmarshalIfTagExists(packets, requiredTag, target); !found {
		return fmt.Errorf("mandatory tag '%s' not found", requiredTag)
	}
	return nil
}

func unmarshalIfTagExists(packets []bertlv.TLV, tag string, target interface{}) bool {
	for _, p := range packets {
		if strings.EqualFold(p.Tag, tag) {
			if err := tlv.UnmarshalFromPackets(p.TLVs, target); err != nil {
				return false
			}
			return true
		}
	}
	return false
}
