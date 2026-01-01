package tlv

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"

	"github.com/moov-io/bertlv"
)

// WriteStructFields inspects a struct and writes its fields to the strings.Builder.
// It joins lines with newlines but DOES NOT add a trailing newline, preventing artifacts in strings.Split.
// If the builder is not empty, it prepends a newline to separate this block from previous content.
func WriteStructFields(sb *strings.Builder, prefix string, s interface{}) {
	val := reflect.ValueOf(s)

	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return
		}
		val = val.Elem()
	}

	typ := val.Type()
	var lines []string

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		if field.Kind() == reflect.Slice && field.Type().Elem().Kind() == reflect.Uint8 {
			if line := formatByteSliceField(prefix, field, fieldType); line != "" {
				lines = append(lines, line)
			}
			continue
		}

		if field.Type() == reflect.TypeOf([]bertlv.TLV{}) {
			if unknownLines := formatUnknownField(prefix, field); len(unknownLines) > 0 {
				lines = append(lines, unknownLines...)
			}
			continue
		}
	}

	if len(lines) > 0 {
		if sb.Len() > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(strings.Join(lines, "\n"))
	}
}

func formatByteSliceField(prefix string, field reflect.Value, fieldType reflect.StructField) string {
	if field.IsNil() || field.Len() == 0 {
		return ""
	}

	bytesVal := field.Bytes()
	formatTag := fieldType.Tag.Get("fmt")
	tlvTag := fieldType.Tag.Get("tlv")

	name := fieldType.Name
	if tlvTag != "" {
		name = fmt.Sprintf("%s (%s)", name, tlvTag)
	}

	displayVal := formatByteValue(bytesVal, formatTag)
	return fmt.Sprintf("    - %s.%s: %s", prefix, name, displayVal)
}

func formatUnknownField(prefix string, field reflect.Value) []string {
	if field.IsNil() || field.Len() == 0 {
		return nil
	}

	var lines []string
	tlvs := field.Interface().([]bertlv.TLV)
	for _, t := range tlvs {
		valStr := strings.ToUpper(hex.EncodeToString(t.Value))
		lines = append(lines, fmt.Sprintf("    - %s.Unknown Tag %s: %s", prefix, t.Tag, valStr))
	}
	return lines
}

func formatByteValue(data []byte, format string) string {
	switch format {
	case "ascii":
		return fmt.Sprintf("%X (%q)", data, MakeSafeASCII(data))
	case "int":
		var integer int
		for _, b := range data {
			integer = (integer << 8) | int(b)
		}
		return fmt.Sprintf("%X (Dec: %d)", data, integer)
	default:
		return strings.ToUpper(hex.EncodeToString(data))
	}
}

func MakeSafeASCII(data []byte) string {
	return strings.Map(func(r rune) rune {
		if r >= 32 && r <= 126 {
			return r
		}
		return '.'
	}, string(data))
}
