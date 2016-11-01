package tlsSyntax

import (
	"bytes"
	"encoding/hex"
	"testing"
)

type ContentType uint8
type ProtocolVersion uint16

type TLSPlaintext struct {
	contentType         ContentType
	legacyRecordVersion ProtocolVersion
	fragment            []byte `tls:"head=2"`
}

type HandshakeType uint8
type Handshake struct {
	msgType HandshakeType
	msgBody []byte `tls:"head=3"`
}

type ExtensionType uint16
type Extension struct {
	extensionType ExtensionType
	extensionData []byte `tls:"head=2"`
}

type Random [32]byte
type CipherSuite uint16

type ClientHello struct {
	legacyVersion            ProtocolVersion
	random                   Random
	legacySessionID          []byte        `tls:"head=1,max=32"`
	cipherSuites             []CipherSuite `tls:"head=2,min=2"`
	legacyCompressionMethods []byte        `tls:"head=1,min=1"`
	extensions               []Extension   `tls:"head=2"`
}

type ServerHello struct {
	version     ProtocolVersion
	random      Random
	cipherSuite CipherSuite
	extensions  []Extension `tls:"head=2"`
}

var (
	extValidIn = Extension{
		extensionType: ExtensionType(0x000a),
		extensionData: []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4},
	}
	extEmptyIn = Extension{
		extensionType: ExtensionType(0x000a),
		extensionData: []byte{},
	}
	extListValidIn  = []Extension{extValidIn, extEmptyIn}
	extListValidHex = "000d000a0005f0f1f2f3f4000a0000"

	helloRandom = [32]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37}
	chValidIn = ClientHello{
		legacyVersion:            0x0303,
		random:                   helloRandom,
		cipherSuites:             []CipherSuite{0x0001, 0x0002, 0x0003},
		legacyCompressionMethods: []byte{0},
		extensions:               extListValidIn,
	}
	chValidHex = "0303" + hex.EncodeToString(helloRandom[:]) + "00" +
		"0006000100020003" + "0100" + extListValidHex

	shValidIn = ServerHello{
		version:     0x7f12,
		random:      helloRandom,
		cipherSuite: CipherSuite(0x0001),
		extensions:  extListValidIn,
	}
	shValidHex = "7f12" + hex.EncodeToString(helloRandom[:]) + "0001" + extListValidHex
)

func TestTLSMarshal(t *testing.T) {
	chValid, _ := hex.DecodeString(chValidHex)
	shValid, _ := hex.DecodeString(shValidHex)

	// ClientHello marshal
	out, err := Marshal(chValidIn)
	if err != nil {
		t.Fatalf("Failed to marshal a valid ClientHello [%v]", err)
	}
	if !bytes.Equal(out, chValid) {
		t.Fatalf("Failed to marshal a valid ClientHello [%x] != [%x]", out, chValid)
	}

	// ServerHello marshal
	out, err = Marshal(shValidIn)
	if err != nil {
		t.Fatalf("Failed to marshal a valid ServerHello [%v]", err)
	}
	if !bytes.Equal(out, shValid) {
		t.Fatalf("Failed to marshal a valid ServerHello [%x] != [%x]", out, shValid)
	}
}
