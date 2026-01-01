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
// It supports multiple occurrences of the same tag if the target field is a slice.
func UnmarshalFromPackets(packets []bertlv.TLV, target interface{}) error {
	v := reflect.ValueOf(target)
	if v.Kind() != reflect.Ptr || v.IsNil() {
		return fmt.Errorf("target must be a non-nil pointer")
	}
	v = v.Elem()
	t := v.Type()

	consumedIndices := make(map[int]bool)

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)
		tagConfig := fieldType.Tag.Get("tlv")

		if tagConfig == "" || tagConfig == ",unknown" || fieldType.Name == "Unknown" {
			continue
		}

		tagHex := strings.ToUpper(strings.Split(tagConfig, ",")[0])

		// Find all packets matching this tag
		for idx, packet := range packets {
			if strings.ToUpper(packet.Tag) == tagHex {
				if err := mapPacketToField(packet, field); err != nil {
					return err
				}
				consumedIndices[idx] = true
			}
		}
	}

	return handleUnknownFields(v, t, packets, consumedIndices)
}

// mapPacketToField dispatches the TLV data to the appropriate reflection logic.
func mapPacketToField(packet bertlv.TLV, field reflect.Value) error {
	// If it's a slice of structs (but not []byte), we grow the slice and use the last element
	if field.Kind() == reflect.Slice && !isByteSlice(field) {
		newElem := reflect.New(field.Type().Elem()).Elem()
		if err := decodeToValue(packet, newElem); err != nil {
			return err
		}
		field.Set(reflect.Append(field, newElem))
		return nil
	}

	return decodeToValue(packet, field)
}

// decodeToValue handles the leaf-node decoding logic (Custom Unmarshaler, ByteSlice, Struct, etc.)
func decodeToValue(packet bertlv.TLV, field reflect.Value) error {
	// 1. Custom Unmarshaler
	if field.CanAddr() {
		if u, ok := field.Addr().Interface().(Unmarshaler); ok {
			return u.UnmarshalTLV(getPacketRawData(packet))
		}
	}

	// 2. Byte Slices
	if isByteSlice(field) {
		field.SetBytes(getPacketRawData(packet))
		return nil
	}

	// 3. Strings (Hex representation)
	if field.Kind() == reflect.String {
		field.SetString(hex.EncodeToString(packet.Value))
		return nil
	}

	// 4. Nested Structures
	if isStructOrPtrToStruct(field) {
		targetField := getTargetField(field)
		if len(packet.TLVs) > 0 {
			return UnmarshalFromPackets(packet.TLVs, targetField.Interface())
		}
		return Unmarshal(packet.Value, targetField.Interface())
	}

	return nil
}

func handleUnknownFields(v reflect.Value, t reflect.Type, packets []bertlv.TLV, consumed map[int]bool) error {
	unknownField, found := findUnknownField(v, t)
	if !found {
		return nil
	}

	var leftovers []bertlv.TLV
	for idx, packet := range packets {
		if !consumed[idx] {
			leftovers = append(leftovers, packet)
		}
	}

	if len(leftovers) > 0 && unknownField.CanSet() {
		unknownField.Set(reflect.ValueOf(leftovers))
	}
	return nil
}

func findUnknownField(v reflect.Value, t reflect.Type) (reflect.Value, bool) {
	for i := 0; i < v.NumField(); i++ {
		tag := t.Field(i).Tag.Get("tlv")
		if tag == ",unknown" || t.Field(i).Name == "Unknown" {
			return v.Field(i), true
		}
	}
	return reflect.Value{}, false
}

func getPacketRawData(p bertlv.TLV) []byte {
	if len(p.TLVs) > 0 {
		if enc, err := bertlv.Encode(p.TLVs); err == nil {
			return enc
		}
	}
	return p.Value
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
