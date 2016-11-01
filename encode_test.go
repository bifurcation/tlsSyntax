package tlsSyntax

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// Test cases to use for encode and decode
var (
	x8 uint8 = 0xA0
	z8       = []byte{0xA0}

	x16    uint16 = 0xB0A0
	z16, _        = hex.DecodeString("B0A0")

	x32    uint32 = 0xD0C0B0A0
	z32, _        = hex.DecodeString("D0C0B0A0")

	x64    uint64 = 0xD0C0B0A090807060
	z64, _        = hex.DecodeString("D0C0B0A090807060")

	xa    = [5]uint16{0x1111, 0x2222, 0x3333, 0x4444, 0x5555}
	za, _ = hex.DecodeString("11112222333344445555")

	xv20    = bytes.Repeat([]byte{0xA0}, 0x20)
	zv20, _ = hex.DecodeString("20" + strings.Repeat("A0", 0x20))

	xv200    = bytes.Repeat([]byte{0xA0}, 0x200)
	zv200, _ = hex.DecodeString("0200" + strings.Repeat("A0", 0x200))

	xv20000    = bytes.Repeat([]byte{0xA0}, 0x20000)
	zv20000, _ = hex.DecodeString("020000" + strings.Repeat("A0", 0x20000))

	xvEhead = struct {
		v []byte `tls:"head=1"`
	}{v: xv200}

	xvEmax = struct {
		v []byte `tls:"max=31"`
	}{v: xv20}

	xvEmin = struct {
		v []byte `tls:"min=33"`
	}{v: xv20}

	xs1 = struct {
		a uint16
		b []uint8 `tls:"head=2"`
		c [4]uint32
	}{
		a: 0xB0A0,
		b: []uint8{0xA0, 0xA1, 0xA2, 0xA3, 0xA4},
		c: [4]uint32{0x10111213, 0x20212223, 0x30313233, 0x40414243},
	}
	zs1, _ = hex.DecodeString("B0A0" + "0005A0A1A2A3A4" + "10111213202122233031323340414243")
)

func TestEncodeBasicTypes(t *testing.T) {
	y8, err := Marshal(x8)
	if err != nil || !bytes.Equal(y8, z8) {
		t.Fatalf("uint8 encode failed [%v] [%x]", err, y8)
	}

	y16, err := Marshal(x16)
	if err != nil || !bytes.Equal(y16, z16) {
		t.Fatalf("uint8 encode failed [%v] [%x]", err, y16)
	}

	y32, err := Marshal(x32)
	if err != nil || !bytes.Equal(y32, z32) {
		t.Fatalf("uint8 encode failed [%v] [%x]", err, y32)
	}

	y64, err := Marshal(x64)
	if err != nil || !bytes.Equal(y64, z64) {
		t.Fatalf("uint8 encode failed [%v] [%x]", err, y64)
	}
}

func TestEncodeArray(t *testing.T) {
	ya, err := Marshal(xa)
	if err != nil || !bytes.Equal(ya, za) {
		t.Fatalf("[5]uint16 encode failed [%v] [%x]", err, ya)
	}
}

func TestEncodeSlice(t *testing.T) {
	yv20, err := Marshal(xv20)
	if err != nil || !bytes.Equal(yv20, zv20) {
		t.Fatalf("[0x20]uint16 encode failed [%v] [%x]", err, yv20)
	}

	yv200, err := Marshal(xv200)
	if err != nil || !bytes.Equal(yv200, zv200) {
		t.Fatalf("[0x200]uint16 encode failed [%v] [%x]", err, yv200)
	}

	yv20000, err := Marshal(xv20000)
	if err != nil || !bytes.Equal(yv20000, zv20000) {
		t.Fatalf("[0x20000]uint16 encode failed [%v] [%x]", err, yv20000)
	}

	yE, err := Marshal(xvEhead)
	if err == nil {
		t.Fatalf("Allowed marshal exceeding header size [%x]", yE)
	}

	yE, err = Marshal(xvEmax)
	if err == nil {
		t.Fatalf("Allowed marshal exceeding max [%x]", yE)
	}

	yE, err = Marshal(xvEmin)
	if err == nil {
		t.Fatalf("Allowed marshal below min [%x]", yE)
	}
}

func TestEncodeStruct(t *testing.T) {
	ys1, err := Marshal(xs1)
	if err != nil || !bytes.Equal(ys1, zs1) {
		t.Fatalf("struct encode failed [%v] [%x]", err, ys1)
	}
}