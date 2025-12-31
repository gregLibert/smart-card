// Package tlv provides high-level utilities for parsing and mapping BER-TLV
// (Basic Encoding Rules - Tag-Length-Value) data into Go structures using struct tags.
package tlv

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"

	"github.com/moov-io/bertlv"
)

// Unmarshaler allows custom types to implement their own TLV parsing logic.
type Unmarshaler interface {
	UnmarshalTLV(data []byte) error
}

// Unmarshal parses raw BER-TLV data and maps it into a target Go struct.
func Unmarshal(data []byte, target interface{}) error {
	packets, err := bertlv.Decode(data)
	if err != nil {
		return fmt.Errorf("bertlv decode failed: %w", err)
	}
	return UnmarshalFromPackets(packets, target)
}

// UnmarshalFromPackets maps a slice of pre-decoded bertlv.TLV objects to a target struct.
//
//nolint:gocyclo // Parsing logic requires handling many types, complexity is expected here
func UnmarshalFromPackets(packets []bertlv.TLV, target interface{}) error {
	v := reflect.ValueOf(target)
	// Ensure the target is a non-nil pointer to a struct
	if v.Kind() != reflect.Ptr || v.IsNil() {
		return fmt.Errorf("target must be a non-nil pointer")
	}
	v = v.Elem()
	t := v.Type()

	// Map packets by their hex tag for faster lookup
	tagMap := make(map[string]bertlv.TLV)
	for _, p := range packets {
		tagMap[strings.ToUpper(p.Tag)] = p
	}

	consumedTags := make(map[string]bool)
	var unknownField reflect.Value
	hasUnknownField := false

	// Iterate through struct fields to map TLV data
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		tagConfig := fieldType.Tag.Get("tlv")

		// The tag name is left empty as this field does not target a specific hex tag.
		// The ",unknown" suffix defines its behavior as a catch-all for all unmapped fields.
		// SHould be read as "<no tag>,unknown"
		if tagConfig == ",unknown" || fieldType.Name == "Unknown" {
			unknownField = field
			hasUnknownField = true
			continue
		}

		if tagConfig == "" {
			continue
		}

		parts := strings.Split(tagConfig, ",")
		tagHex := strings.ToUpper(parts[0])

		packet, exists := tagMap[tagHex]
		if !exists {
			continue
		}

		consumedTags[tagHex] = true

		// Check for custom Unmarshaler implementation
		if field.CanAddr() {
			if u, ok := field.Addr().Interface().(Unmarshaler); ok {
				data := packet.Value
				if len(packet.TLVs) > 0 {
					if enc, err := bertlv.Encode(packet.TLVs); err == nil {
						data = enc
					}
				}
				if err := u.UnmarshalTLV(data); err != nil {
					return fmt.Errorf("custom unmarshal failed for tag %s: %w", tagHex, err)
				}
				continue
			}
		}

		// Handle byte slices (direct value copy)
		if isByteSlice(field) {
			if len(packet.Value) > 0 {
				field.SetBytes(packet.Value)
			} else if len(packet.TLVs) > 0 {
				encodedChildren, err := bertlv.Encode(packet.TLVs)
				if err == nil {
					field.SetBytes(encodedChildren)
				}
			}
			continue
		}

		// Handle strings as hexadecimal representation
		if field.Kind() == reflect.String {
			field.SetString(hex.EncodeToString(packet.Value))
			continue
		}

		// Handle nested structures
		if isStructOrPtrToStruct(field) && !isByteSlice(field) {
			targetField := getTargetField(field)
			if len(packet.TLVs) > 0 {
				if err := UnmarshalFromPackets(packet.TLVs, targetField.Interface()); err != nil {
					return err
				}
			} else {
				if err := Unmarshal(packet.Value, targetField.Interface()); err != nil {
					return err
				}
			}
			continue
		}
	}

	// Capture all tags that were not mapped to a specific field
	if hasUnknownField {
		var leftovers []bertlv.TLV
		for tag, packet := range tagMap {
			if !consumedTags[tag] {
				leftovers = append(leftovers, packet)
			}
		}

		if len(leftovers) > 0 && unknownField.CanSet() {
			unknownField.Set(reflect.ValueOf(leftovers))
		}
	}

	return nil
}

// GetValue scans the raw data for a specific tag and returns its raw payload.
func GetValue(data []byte, tag uint) ([]byte, error) {
	packets, err := bertlv.Decode(data)
	if err != nil {
		return nil, err
	}

	targetTag := strings.ToUpper(fmt.Sprintf("%X", tag))

	for _, p := range packets {
		if strings.ToUpper(p.Tag) == targetTag {
			if len(p.TLVs) > 0 {
				return bertlv.Encode(p.TLVs)
			}
			return p.Value, nil
		}
	}
	return nil, fmt.Errorf("tag %s not found", targetTag)
}

func isByteSlice(v reflect.Value) bool {
	return v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8
}

func isStructOrPtrToStruct(v reflect.Value) bool {
	if v.Kind() == reflect.Struct {
		return true
	}
	if v.Kind() == reflect.Ptr && v.Type().Elem().Kind() == reflect.Struct {
		return true
	}
	return false
}

func getTargetField(field reflect.Value) reflect.Value {
	if field.Kind() == reflect.Ptr {
		if field.IsNil() {
			field.Set(reflect.New(field.Type().Elem()))
		}
		return field
	}
	return field.Addr()
}
