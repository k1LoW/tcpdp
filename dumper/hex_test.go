package dumper

import (
	"bytes"
	"testing"
)

var hexReadTests = []struct {
	description string
	in          []byte
	direction   Direction
	expected    []DumpValue
}{
	{
		"MySQL HandshakeResponse41 packet (https://dev.mysql.com/doc/internals/en/connection-phase-packets.html)",
		// https://dev.mysql.com/doc/internals/en/connection-phase-packets.html
		[]byte{
			0x54, 0x00, 0x00, 0x01, 0x8d, 0xa6, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x70, 0x61, 0x6d, 0x00, 0x14, 0xab, 0x09, 0xee, 0xf6, 0xbc, 0xb1, 0x32,
			0x3e, 0x61, 0x14, 0x38, 0x65, 0xc0, 0x99, 0x1d, 0x95, 0x7d, 0x75, 0xd4, 0x47, 0x74, 0x65, 0x73,
			0x74, 0x00, 0x6d, 0x79, 0x73, 0x71, 0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x70,
			0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00,
		},
		SrcToDst,
		[]DumpValue{
			DumpValue{
				Key:   "bytes",
				Value: "54 00 00 01 8d a6 0f 00 00 00 00 01 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 70 61 6d 00 14 ab 09 ee f6 bc b1 32 3e 61 14 38 65 c0 99 1d 95 7d 75 d4 47 74 65 73 74 00 6d 79 73 71 6c 5f 6e 61 74 69 76 65 5f 70 61 73 73 77 6f 72 64 00",
			},
			DumpValue{
				Key:   "ascii",
				Value: "T...................................pam........2>a.8e....}u.Gtest.mysql_native_password.",
			},
		},
	},
	{
		"MySQL COM_QUERY packet",
		[]byte{
			0x14, 0x00, 0x00, 0x00, 0x03, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x20, 0x2a, 0x20, 0x66, 0x72,
			0x6f, 0x6d, 0x20, 0x70, 0x6f, 0x73, 0x74, 0x73,
		},
		SrcToDst,
		[]DumpValue{
			DumpValue{
				Key:   "bytes",
				Value: "14 00 00 00 03 73 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 70 6f 73 74 73",
			},
			DumpValue{
				Key:   "ascii",
				Value: ".....select * from posts",
			},
		},
	},
}

func TestHexRead(t *testing.T) {
	for _, tt := range hexReadTests {
		out := new(bytes.Buffer)
		dumper := &HexDumper{
			logger: newTestLogger(out),
		}
		in := tt.in
		direction := tt.direction
		connMetadata := dumper.NewConnMetadata()

		actual := dumper.Read(in, direction, connMetadata)
		expected := tt.expected

		if len(actual) != len(expected) {
			t.Errorf("actual %v\nwant %v", actual, expected)
		}
		for i := 0; i < len(actual); i++ {
			v := actual[i].Value
			ev := expected[i].Value
			switch v.(type) {
			case []interface{}:
				for j := 0; j < len(v.([]interface{})); j++ {
					if v.([]interface{})[j] != ev.([]interface{})[j] {
						t.Errorf("actual %#v\nwant %#v", v.([]interface{})[j], ev.([]interface{})[j])
					}
				}
			default:
				if actual[i] != expected[i] {
					t.Errorf("actual %#v\nwant %#v", actual[i], expected[i])
				}
			}
		}
	}
}
