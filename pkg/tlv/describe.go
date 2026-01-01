package tlv

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"

	"github.com/moov-io/bertlv"
)

// WriteStructFields inspects a struct using reflection and writes its fields to the strings.Builder
// in a standardized format: "- Prefix.FieldName (Tag): HexValue (Interpretation)".
// It handles fields tagged with `tlv` and `fmt`.
func WriteStructFields(sb *strings.Builder, prefix string, s interface{}) {
	val := reflect.ValueOf(s)

	// Handle pointer dereference
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return
		}
		val = val.Elem()
	}

	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		// Handle []byte fields
		if field.Kind() == reflect.Slice && field.Type().Elem().Kind() == reflect.Uint8 {
			if !field.IsNil() && field.Len() > 0 {
				bytesVal := field.Bytes()
				formatTag := fieldType.Tag.Get("fmt")
				tlvTag := fieldType.Tag.Get("tlv")

				name := fieldType.Name
				if tlvTag != "" {
					name = fmt.Sprintf("%s (%s)", name, tlvTag)
				}

				displayVal := ""
				switch formatTag {
				case "ascii":
					displayVal = fmt.Sprintf("%X (%q)", bytesVal, MakeSafeASCII(bytesVal))
				case "int":
					var integer int
					for _, b := range bytesVal {
						integer = (integer << 8) | int(b)
					}
					displayVal = fmt.Sprintf("%X (Dec: %d)", bytesVal, integer)
				default:
					displayVal = strings.ToUpper(hex.EncodeToString(bytesVal))
				}
				sb.WriteString(fmt.Sprintf("    - %s.%s: %s\n", prefix, name, displayVal))
			}
		}

		// Handle Unknown TLV slices
		if field.Type() == reflect.TypeOf([]bertlv.TLV{}) {
			if !field.IsNil() && field.Len() > 0 {
				tlvs := field.Interface().([]bertlv.TLV)
				for _, t := range tlvs {
					valStr := strings.ToUpper(hex.EncodeToString(t.Value))
					sb.WriteString(fmt.Sprintf("    - %s.Unknown Tag %s: %s\n", prefix, t.Tag, valStr))
				}
			}
		}
	}
}

// MakeSafeASCII converts non-printable characters to dots.
func MakeSafeASCII(data []byte) string {
	return strings.Map(func(r rune) rune {
		if r >= 32 && r <= 126 {
			return r
		}
		return '.'
	}, string(data))
}
