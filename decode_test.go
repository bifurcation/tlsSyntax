package tlsSyntax

import (
	"reflect"
	"testing"
)

func TestDecodeBasicTypes(t *testing.T) {
	var y8 uint8
	err := Unmarshal(z8, &y8)
	if err != nil || y8 != x8 {
		t.Fatalf("uint8 decode failed [%v] [%x]", err, y8)
	}

	var y16 uint16
	err = Unmarshal(z16, &y16)
	if err != nil || y16 != x16 {
		t.Fatalf("uint16 decode failed [%v] [%x]", err, y16)
	}

	var y32 uint32
	err = Unmarshal(z32, &y32)
	if err != nil || y32 != x32 {
		t.Fatalf("uint32 decode failed [%v] [%x]", err, y32)
	}

	var y64 uint64
	err = Unmarshal(z64, &y64)
	if err != nil || y64 != x64 {
		t.Fatalf("uint64 decode failed [%v] [%x]", err, y64)
	}
}

func TestDecodeArray(t *testing.T) {
	var ya [5]uint16
	err := Unmarshal(za, &ya)
	if err != nil || !reflect.DeepEqual(ya, xa) {
		t.Fatalf("[5]uint16 encode failed [%v] [%x]", err, ya)
	}
}
