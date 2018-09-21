package dumper

import (
	"bytes"
	"strings"
	"testing"
)

var mysqlReadTests = []struct {
	description   string
	in            []byte
	direction     Direction
	connMetadata  *ConnMetadata
	expected      []DumpValue
	expectedQuery []DumpValue
	logContain    string
}{
	{
		"Parse username/database from HandshakeResponse41 packet (https://dev.mysql.com/doc/internals/en/connection-phase-packets.html)",
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
		&ConnMetadata{
			DumpValues: []DumpValue{},
			Internal:   stmtNumParams{5: 2},
		},
		[]DumpValue{
			DumpValue{
				Key:   "username",
				Value: "pam",
			},
			DumpValue{
				Key:   "database",
				Value: "test",
			},
		},
		[]DumpValue{},
		"",
	},
	{
		"Parse username/database from HandshakeResponse41 packet",
		[]byte{
			0xc1, 0x00, 0x00, 0x01, 0x0d, 0xa6, 0xff, 0x01, 0x00, 0x00, 0x00, 0x01, 0x21, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x72, 0x6f, 0x6f, 0x74, 0x00, 0x14, 0x45, 0x98, 0xce, 0xe1, 0x13, 0xfa,
			0xe5, 0xe3, 0x37, 0x9f, 0xc7, 0x3a, 0x61, 0xa1, 0x7e, 0xc6, 0x33, 0x73, 0x57, 0x18, 0x74, 0x65,
			0x73, 0x74, 0x64, 0x62, 0x00, 0x6d, 0x79, 0x73, 0x71, 0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69, 0x76,
			0x65, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00, 0x69, 0x03, 0x5f, 0x6f, 0x73,
			0x08, 0x6f, 0x73, 0x78, 0x31, 0x30, 0x2e, 0x31, 0x33, 0x0c, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e,
			0x74, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x08, 0x6c, 0x69, 0x62, 0x6d, 0x79, 0x73, 0x71, 0x6c, 0x04,
			0x5f, 0x70, 0x69, 0x64, 0x05, 0x31, 0x36, 0x37, 0x30, 0x33, 0x0f, 0x5f, 0x63, 0x6c, 0x69, 0x65,
			0x6e, 0x74, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x06, 0x35, 0x2e, 0x37, 0x2e, 0x32,
			0x33, 0x09, 0x5f, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x06, 0x78, 0x38, 0x36, 0x5f,
			0x36, 0x34, 0x0c, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x05,
			0x6d, 0x79, 0x73, 0x71, 0x6c,
		},
		SrcToDst,
		&ConnMetadata{
			DumpValues: []DumpValue{},
			Internal:   stmtNumParams{5: 2},
		},
		[]DumpValue{
			DumpValue{
				Key:   "username",
				Value: "root",
			},
			DumpValue{
				Key:   "database",
				Value: "testdb",
			},
		},
		[]DumpValue{},
		"",
	},
	{
		"Parse query from COM_QUERY packet",
		[]byte{
			0x14, 0x00, 0x00, 0x00, 0x03, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x20, 0x2a, 0x20, 0x66, 0x72,
			0x6f, 0x6d, 0x20, 0x70, 0x6f, 0x73, 0x74, 0x73,
		},
		SrcToDst,
		&ConnMetadata{
			DumpValues: []DumpValue{},
			Internal:   stmtNumParams{5: 2},
		},
		[]DumpValue{},
		[]DumpValue{
			DumpValue{
				Key:   "query",
				Value: "select * from posts",
			},
			DumpValue{
				Key:   "seq_num",
				Value: int64(0),
			},
			DumpValue{
				Key:   "command_id",
				Value: byte(3),
			},
		},
		"",
	},
	{
		"When direction = RemoteToClient do not parse query",
		[]byte{
			0x14, 0x00, 0x00, 0x00, 0x03, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x20, 0x2a, 0x20, 0x66, 0x72,
			0x6f, 0x6d, 0x20, 0x70, 0x6f, 0x73, 0x74, 0x73,
		},
		RemoteToClient,
		&ConnMetadata{
			DumpValues: []DumpValue{},
			Internal:   stmtNumParams{5: 2},
		},
		[]DumpValue{},
		[]DumpValue{},
		"",
	},
	{
		"",
		[]byte{
			0x25, 0x00, 0x00, 0x00, 0x17, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01,
			0xfe, 0x00, 0xfe, 0x00, 0x06, 0x74, 0x65, 0x73, 0x74, 0x64, 0x62, 0x0d, 0x63, 0x6f, 0x6d, 0x6d,
			0x65, 0x6e, 0x74, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x73,
		},
		ClientToRemote,
		&ConnMetadata{
			DumpValues: []DumpValue{},
			Internal:   stmtNumParams{5: 2},
		},
		[]DumpValue{},
		[]DumpValue{
			DumpValue{
				Key:   "stmt_id",
				Value: 5,
			},
			DumpValue{
				Key:   "stmt_execute_values",
				Value: []interface{}{"testdb", "comment_stars"},
			},
			DumpValue{
				Key:   "seq_num",
				Value: int64(0),
			},
			DumpValue{
				Key:   "command_id",
				Value: byte(23),
			},
		},
		"",
	},
}

func TestMysqlReadInitialDumpValuesHandshakeResponse41(t *testing.T) {
	for _, tt := range mysqlReadTests {
		out := new(bytes.Buffer)
		dumper := &MysqlDumper{
			logger: newTestLogger(out),
		}
		in := tt.in
		direction := tt.direction
		connMetadata := tt.connMetadata

		actual := dumper.ReadInitialDumpValues(in, direction, connMetadata)
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

func TestMysqlRead(t *testing.T) {
	for _, tt := range mysqlReadTests {
		out := new(bytes.Buffer)
		dumper := &MysqlDumper{
			logger: newTestLogger(out),
		}
		in := tt.in
		direction := tt.direction
		connMetadata := tt.connMetadata

		actual := dumper.Read(in, direction, connMetadata)
		expected := tt.expectedQuery

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

func TestMysqlAnalyzeUsernameAndDatabase(t *testing.T) {
	for _, tt := range mysqlReadTests {
		out := new(bytes.Buffer)
		dumper := &MysqlDumper{
			logger: newTestLogger(out),
		}
		in := tt.in
		direction := ClientToRemote
		connMetadata := tt.connMetadata
		additional := []DumpValue{}

		err := dumper.Dump(in, direction, connMetadata, additional)
		if err != nil {
			t.Errorf("%v", err)
		}

		expected := tt.expected

		actual := connMetadata.DumpValues
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

		log := out.String()

		if !strings.Contains(log, tt.logContain) {
			t.Errorf("%v not be %v", log, tt.logContain)
		}
	}
}

var mysqlLengthEncodedIntegerTests = []struct {
	in       []byte
	expected uint64
}{
	{
		[]byte{0xfa},
		250,
	},
	{
		[]byte{0xfc, 0xfb, 0x00},
		251,
	},
}

func TestMysqlReadLengthEncodeInteger(t *testing.T) {
	for _, tt := range mysqlLengthEncodedIntegerTests {
		buff := bytes.NewBuffer(tt.in)
		actual := readLengthEncodedInteger(buff)
		if actual != tt.expected {
			t.Errorf("actual %#v\nwant %#v", actual, tt.expected)
		}
	}
}

var mysqlBinaryProtocolValueTests = []struct {
	in       []byte
	t        mysqlType
	expected interface{}
}{
	{
		[]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		mysqlTypeLonglong,
		uint64(1),
	},
	{
		[]byte{0x01, 0x00, 0x00, 0x00},
		mysqlTypeLong,
		uint64(1),
	},
	{
		[]byte{0x01, 0x00, 0x00, 0x00},
		mysqlTypeInt24,
		uint64(1),
	},
	{
		[]byte{0x01, 0x00},
		mysqlTypeShort,
		uint64(1),
	},
	{
		[]byte{0xe2, 0x07},
		mysqlTypeYear,
		uint64(2018),
	},
	{
		[]byte{0x01},
		mysqlTypeTiny,
		uint64(1),
	},
	{
		[]byte{0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x24, 0x40},
		mysqlTypeDouble,
		10.2,
	},
	{
		[]byte{0x33, 0x33, 0x23, 0x41},
		mysqlTypeFloat,
		float32(10.2),
	},
	{
		[]byte{0x04, 0xda, 0x07, 0x0a, 0x11},
		mysqlTypeDate,
		"2010-10-17",
	},
	{
		[]byte{0x0b, 0xda, 0x07, 0x0a, 0x11, 0x13, 0x1b, 0x1e, 0x01, 0x00, 0x00, 0x00},
		mysqlTypeDatetime,
		"2010-10-17 19:27:30.000 001",
	},
	{
		[]byte{0x0b, 0xda, 0x07, 0x0a, 0x11, 0x13, 0x1b, 0x1e, 0x01, 0x00, 0x00, 0x00},
		mysqlTypeTimestamp,
		"2010-10-17 19:27:30.000 001",
	},
	{
		[]byte{0x0c, 0x01, 0x78, 0x00, 0x00, 0x00, 0x13, 0x1b, 0x1e, 0x01, 0x00, 0x00, 0x00},
		mysqlTypeTime,
		"-120d 19:27:30.000 001",
	},
	{
		[]byte{0x08, 0x01, 0x78, 0x00, 0x00, 0x00, 0x13, 0x1b, 0x1e},
		mysqlTypeTime,
		"-120d 19:27:30",
	},
	{
		[]byte{0x01},
		mysqlTypeTime,
		"0d 00:00:00",
	},
	{
		[]byte{},
		mysqlTypeNull,
		nil,
	},
	{
		[]byte{0x03, 0x66, 0x6f, 0x6f},
		mysqlTypeString,
		"foo",
	},
}

func TestMysqlReadBinaryProtocolValue(t *testing.T) {
	for _, tt := range mysqlBinaryProtocolValueTests {
		buff := bytes.NewBuffer(tt.in)
		actual := readBinaryProtocolValue(buff, tt.t)
		if actual != tt.expected {
			t.Errorf("actual %#v\nwant %#v", actual, tt.expected)
		}
	}
}
