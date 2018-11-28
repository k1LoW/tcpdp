package mysql

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/k1LoW/tcpdp/dumper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type mysqlReadTest struct {
	description   string
	in            []byte
	direction     dumper.Direction
	connMetadata  dumper.ConnMetadata
	expected      []dumper.DumpValue
	expectedQuery []dumper.DumpValue
	logContain    string
}

var mysqlReadTests = []mysqlReadTest{
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
		dumper.SrcToDst,
		dumper.ConnMetadata{
			DumpValues: []dumper.DumpValue{},
			Internal: connMetadataInternal{
				stmtNumParams:      stmtNumParams{5: 2},
				clientCapabilities: clientCapabilities{},
				charSet:            charSetUnknown,
			},
		},
		[]dumper.DumpValue{
			dumper.DumpValue{
				Key:   "character_set",
				Value: "latin1",
			},
			dumper.DumpValue{
				Key:   "username",
				Value: "pam",
			},
			dumper.DumpValue{
				Key:   "database",
				Value: "test",
			},
		},
		[]dumper.DumpValue{},
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
		dumper.SrcToDst,
		dumper.ConnMetadata{
			DumpValues: []dumper.DumpValue{},
			Internal: connMetadataInternal{
				stmtNumParams:      stmtNumParams{5: 2},
				clientCapabilities: clientCapabilities{},
				charSet:            charSetUnknown,
			},
		},
		[]dumper.DumpValue{
			dumper.DumpValue{
				Key:   "character_set",
				Value: "utf8",
			},
			dumper.DumpValue{
				Key:   "username",
				Value: "root",
			},
			dumper.DumpValue{
				Key:   "database",
				Value: "testdb",
			},
		},
		[]dumper.DumpValue{},
		"",
	},
	{
		"Parse username/database from HandshakeResponse320 packet (https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse320)",
		// https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse320
		[]byte{
			0x11, 0x00, 0x00, 0x01, 0x85, 0x24, 0x00, 0x00, 0x00, 0x6f, 0x6c, 0x64, 0x00, 0x47, 0x44, 0x53,
			0x43, 0x51, 0x59, 0x52, 0x5f,
		},
		dumper.SrcToDst,
		dumper.ConnMetadata{
			DumpValues: []dumper.DumpValue{},
			Internal: connMetadataInternal{
				stmtNumParams:      stmtNumParams{5: 2},
				clientCapabilities: clientCapabilities{},
				charSet:            charSetUnknown,
			},
		},
		[]dumper.DumpValue{
			dumper.DumpValue{
				Key:   "username",
				Value: "old",
			},
		},
		[]dumper.DumpValue{},
		"",
	},
	{
		"Parse username/database from HandshakeResponse320 packet",
		[]byte{
			0x11, 0x00, 0x00, 0x01, 0x8d, 0x24, 0x00, 0x00, 0x00, 0x72, 0x6f, 0x6f, 0x74, 0x00, 0x00, 0x74,
			0x65, 0x73, 0x74, 0x64, 0x62,
		},
		dumper.SrcToDst,
		dumper.ConnMetadata{
			DumpValues: []dumper.DumpValue{},
			Internal: connMetadataInternal{
				stmtNumParams:      stmtNumParams{},
				clientCapabilities: clientCapabilities{},
				charSet:            charSetUnknown,
			},
		},
		[]dumper.DumpValue{
			dumper.DumpValue{
				Key:   "username",
				Value: "root",
			},
			dumper.DumpValue{
				Key:   "database",
				Value: "testdb",
			},
		},
		[]dumper.DumpValue{},
		"",
	},
	{
		"Parse query from COM_QUERY packet",
		[]byte{
			0x14, 0x00, 0x00, 0x00, 0x03, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x20, 0x2a, 0x20, 0x66, 0x72,
			0x6f, 0x6d, 0x20, 0x70, 0x6f, 0x73, 0x74, 0x73,
		},
		dumper.SrcToDst,
		dumper.ConnMetadata{
			DumpValues: []dumper.DumpValue{},
			Internal: connMetadataInternal{
				stmtNumParams:      stmtNumParams{5: 2},
				clientCapabilities: clientCapabilities{},
				charSet:            charSetUnknown,
			},
		},
		[]dumper.DumpValue{},
		[]dumper.DumpValue{
			dumper.DumpValue{
				Key:   "query",
				Value: "select * from posts",
			},
			dumper.DumpValue{
				Key:   "seq_num",
				Value: int64(0),
			},
			dumper.DumpValue{
				Key:   "command_id",
				Value: byte(3),
			},
		},
		"\"query\":\"select * from posts\"",
	},
	{
		"When direction = dumper.RemoteToClient do not parse query",
		[]byte{
			0x14, 0x00, 0x00, 0x00, 0x03, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x20, 0x2a, 0x20, 0x66, 0x72,
			0x6f, 0x6d, 0x20, 0x70, 0x6f, 0x73, 0x74, 0x73,
		},
		dumper.RemoteToClient,
		dumper.ConnMetadata{
			DumpValues: []dumper.DumpValue{},
			Internal: connMetadataInternal{
				stmtNumParams:      stmtNumParams{5: 2},
				clientCapabilities: clientCapabilities{},
				charSet:            charSetUnknown,
			},
		},
		[]dumper.DumpValue{},
		[]dumper.DumpValue{},
		"",
	},
	{
		"Parse values from COM_STMT_EXECUTE packet",
		[]byte{
			0x25, 0x00, 0x00, 0x00, 0x17, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01,
			0xfe, 0x00, 0xfe, 0x00, 0x06, 0x74, 0x65, 0x73, 0x74, 0x64, 0x62, 0x0d, 0x63, 0x6f, 0x6d, 0x6d,
			0x65, 0x6e, 0x74, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x73,
		},
		dumper.ClientToRemote,
		dumper.ConnMetadata{
			DumpValues: []dumper.DumpValue{},
			Internal: connMetadataInternal{
				stmtNumParams:      stmtNumParams{5: 2},
				clientCapabilities: clientCapabilities{},
				charSet:            charSetUnknown,
			},
		},
		[]dumper.DumpValue{},
		[]dumper.DumpValue{
			dumper.DumpValue{
				Key:   "stmt_id",
				Value: 5,
			},
			dumper.DumpValue{
				Key:   "stmt_execute_values",
				Value: []interface{}{"testdb", "comment_stars"},
			},
			dumper.DumpValue{
				Key:   "seq_num",
				Value: int64(0),
			},
			dumper.DumpValue{
				Key:   "command_id",
				Value: byte(23),
			},
		},
		"\"stmt_execute_values\":[\"testdb\",\"comment_stars\"]",
	},
	{
		// https://dev.mysql.com/doc/internals/en/example-one-mysql-packet.html
		"Parse values from Compressed COM_QUERY (Client Compress ON)",
		[]byte{
			0x22, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x78, 0x9c, 0xd3, 0x63, 0x60, 0x60, 0x60, 0x2e, 0x4e,
			0xcd, 0x49, 0x4d, 0x2e, 0x51, 0x50, 0x32, 0x30, 0x34, 0x32, 0x36, 0x31, 0x35, 0x33, 0xb7, 0xb0,
			0xc4, 0xcd, 0x52, 0x02, 0x00, 0x0c, 0xd1, 0x0a, 0x6c,
		},
		dumper.ClientToRemote,
		dumper.ConnMetadata{
			DumpValues: []dumper.DumpValue{},
			Internal: connMetadataInternal{
				stmtNumParams:      stmtNumParams{5: 2},
				clientCapabilities: clientCapabilities{clientCompress: true},
				charSet:            charSetUnknown,
			},
		},
		[]dumper.DumpValue{},
		[]dumper.DumpValue{
			dumper.DumpValue{
				Key:   "query",
				Value: "select \"012345678901234567890123456789012345\"",
			},
			dumper.DumpValue{
				Key:   "seq_num",
				Value: int64(0),
			},
			dumper.DumpValue{
				Key:   "command_id",
				Value: byte(3),
			},
		},
		"\"query\":\"select \\\"012345678901234567890123456789012345\\\"\"",
	},
	{
		"Parse values from Uncompressed COM_QUERY (Client Compress ON)",
		[]byte{
			0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x03, 0x53, 0x45, 0x4c, 0x45,
			0x43, 0x54, 0x20, 0x2a, 0x20, 0x46, 0x52, 0x4f, 0x4d, 0x20, 0x69, 0x6e, 0x66, 0x6f, 0x72, 0x6d,
			0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x2e, 0x74, 0x61, 0x62,
			0x6c, 0x65, 0x73,
		},
		dumper.ClientToRemote,
		dumper.ConnMetadata{
			DumpValues: []dumper.DumpValue{},
			Internal: connMetadataInternal{
				stmtNumParams:      stmtNumParams{5: 2},
				clientCapabilities: clientCapabilities{clientCompress: true},
				charSet:            charSetUnknown,
			},
		},
		[]dumper.DumpValue{},
		[]dumper.DumpValue{
			dumper.DumpValue{
				Key:   "query",
				Value: "SELECT * FROM information_schema.tables",
			},
			dumper.DumpValue{
				Key:   "seq_num",
				Value: int64(0),
			},
			dumper.DumpValue{
				Key:   "command_id",
				Value: byte(3),
			},
		},
		"\"query\":\"SELECT * FROM information_schema.tables\"",
	},
	{
		"Parse values from Compressed COM_STMT_PREPARE (Client Compress ON)",
		[]byte{
			0x60, 0x00, 0x00, 0x00, 0x10, 0x01, 0x00, 0x78, 0x9c, 0xe2, 0x61, 0x64, 0x60, 0x10, 0x0b, 0x76,
			0xf5, 0x71, 0x75, 0x0e, 0x51, 0x70, 0xf6, 0xf7, 0x73, 0x76, 0x0c, 0xd1, 0xb0, 0xd7, 0x51, 0x80,
			0x20, 0x25, 0x85, 0x92, 0xe4, 0x82, 0x94, 0x02, 0x85, 0xcc, 0x62, 0x85, 0x10, 0xe7, 0x00, 0x85,
			0x94, 0xd2, 0xdc, 0x02, 0x85, 0x92, 0xfc, 0xfc, 0x1c, 0x85, 0xf2, 0xcc, 0x92, 0x0c, 0x85, 0xe4,
			0xd2, 0xe2, 0x92, 0xfc, 0x5c, 0xb0, 0x68, 0x6a, 0x91, 0x42, 0x79, 0x51, 0x66, 0x49, 0x49, 0x6a,
			0x9e, 0x42, 0x66, 0x9e, 0x82, 0x7b, 0xbe, 0x9e, 0xd2, 0x10, 0xd5, 0xac, 0x69, 0x0d, 0x08, 0x00,
			0x00, 0xff, 0xff, 0xb6, 0xf5, 0x59, 0x55,
		},
		dumper.ClientToRemote,
		dumper.ConnMetadata{
			DumpValues: []dumper.DumpValue{},
			Internal: connMetadataInternal{
				stmtNumParams:      stmtNumParams{},
				clientCapabilities: clientCapabilities{clientCompress: true},
				charSet:            charSetUnknown,
			},
		},
		[]dumper.DumpValue{},
		[]dumper.DumpValue{
			dumper.DumpValue{
				Key:   "stmt_prepare_query",
				Value: "SELECT CONCAT(?, ?, ?, \" tcpdp is TCP dump tool with custom dumper written in Go.\", \" tcpdp is TCP dump tool with custom dumper written in Go.\", \" tcpdp is TCP dump tool with custom dumper written in Go.\", \" tcpdp is TCP dump tool with custom dumper written in Go.\");",
			},
			dumper.DumpValue{
				Key:   "seq_num",
				Value: int64(0),
			},
			dumper.DumpValue{
				Key:   "command_id",
				Value: byte(22),
			},
		},
		"\"stmt_prepare_query\":\"SELECT CONCAT(?, ?, ?, \\\" tcpdp is TCP dump tool with custom dumper written in Go.\\\", \\\" tcpdp is TCP dump tool with custom dumper written in Go.\\\", \\\" tcpdp is TCP dump tool with custom dumper written in Go.\\\", \\\" tcpdp is TCP dump tool with custom dumper written in Go.\\\");\"",
	},
	{
		"Parse values from Compressed COM_STMT_EXECUTE (Client Compress ON)",
		[]byte{
			0x40, 0x00, 0x00, 0x00, 0x1c, 0x01, 0x00, 0x78, 0x9c, 0x92, 0x60, 0x64, 0x60, 0x10, 0x67, 0x66,
			0x60, 0x60, 0x60, 0x60, 0x04, 0x13, 0xff, 0x18, 0x40, 0x90, 0xb5, 0x24, 0xb9, 0x20, 0xa5, 0xe0,
			0xcf, 0x1f, 0x86, 0xc7, 0xcd, 0x6d, 0x8f, 0x9b, 0x16, 0x3f, 0x6e, 0xde, 0xf3, 0xb8, 0x69, 0x3b,
			0x88, 0x6c, 0x9e, 0x02, 0x26, 0xdb, 0xa1, 0x82, 0x50, 0xee, 0xf0, 0x54, 0xc3, 0x00, 0x08, 0x00,
			0x00, 0xff, 0xff, 0x63, 0x8d, 0xb3, 0xbd,
		},
		dumper.ClientToRemote,
		dumper.ConnMetadata{
			DumpValues: []dumper.DumpValue{},
			Internal: connMetadataInternal{
				stmtNumParams:      stmtNumParams{3: 3},
				clientCapabilities: clientCapabilities{clientCompress: true},
				charSet:            charSetUnknown,
			},
		},
		[]dumper.DumpValue{},
		[]dumper.DumpValue{
			dumper.DumpValue{
				Key:   "stmt_id",
				Value: 3,
			},
			dumper.DumpValue{
				Key:   "stmt_execute_values",
				Value: []interface{}{"tcpdp", "ティーシーピーディーピーティーシーピーディーピーティーシーピーディーピーティーシーピーディーピーティーシーピーディーピーティーシーピーディーピーティーシーピーディーピー", ""},
			},
			dumper.DumpValue{
				Key:   "seq_num",
				Value: int64(0),
			},
			dumper.DumpValue{
				Key:   "command_id",
				Value: byte(23),
			},
		},
		"\"stmt_execute_values\":[\"tcpdp\",\"ティーシーピーディーピーティーシーピーディーピーティーシーピーディーピーティーシーピーディーピーティーシーピーディーピーティーシーピーディーピーティーシーピーディーピー\",\"\"]",
	},
	{
		"Parse values from Uncompressed COM_STMT_PREPARE (Client Compress ON)",
		[]byte{
			0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x16, 0x53, 0x45, 0x4c, 0x45,
			0x43, 0x54, 0x20, 0x3f, 0x20, 0x2b, 0x20, 0x3f, 0x20, 0x2b, 0x20, 0x3f,
		},
		dumper.ClientToRemote,
		dumper.ConnMetadata{
			DumpValues: []dumper.DumpValue{},
			Internal: connMetadataInternal{
				stmtNumParams:      stmtNumParams{},
				clientCapabilities: clientCapabilities{clientCompress: true},
				charSet:            charSetUnknown,
			},
		},
		[]dumper.DumpValue{},
		[]dumper.DumpValue{
			dumper.DumpValue{
				Key:   "stmt_prepare_query",
				Value: "SELECT ? + ? + ?",
			},
			dumper.DumpValue{
				Key:   "seq_num",
				Value: int64(0),
			},
			dumper.DumpValue{
				Key:   "command_id",
				Value: byte(22),
			},
		},
		"\"stmt_prepare_query\":\"SELECT ? + ? + ?\"",
	},
	{
		"Parse values from Uncompressed COM_STMT_EXECUTE (Client Compress ON)",
		[]byte{
			0x2e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x17, 0x02, 0x00, 0x00, 0x00,
			0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x05, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x37, 0x40, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00,
		},
		dumper.ClientToRemote,
		dumper.ConnMetadata{
			DumpValues: []dumper.DumpValue{},
			Internal: connMetadataInternal{
				stmtNumParams:      stmtNumParams{2: 3},
				clientCapabilities: clientCapabilities{clientCompress: true},
				charSet:            charSetUnknown,
			},
		},
		[]dumper.DumpValue{},
		[]dumper.DumpValue{
			dumper.DumpValue{
				Key:   "stmt_id",
				Value: 2,
			},
			dumper.DumpValue{
				Key:   "stmt_execute_values",
				Value: []interface{}{int64(1), 23.4, int64(0)},
			},
			dumper.DumpValue{
				Key:   "seq_num",
				Value: int64(0),
			},
			dumper.DumpValue{
				Key:   "command_id",
				Value: byte(23),
			},
		},
		"\"stmt_execute_values\":[1,23.4,0]",
	},
	{
		"tcpdp mysql dumper not support SSL connection (https://dev.mysql.com/doc/internals/en/ssl.html)",
		[]byte{
			0x20, 0x00, 0x00, 0x01, 0x05, 0xae, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		},
		dumper.ClientToRemote,
		dumper.ConnMetadata{
			DumpValues: []dumper.DumpValue{},
			Internal: connMetadataInternal{
				stmtNumParams:      stmtNumParams{},
				clientCapabilities: clientCapabilities{},
				charSet:            charSetUnknown,
			},
		},
		[]dumper.DumpValue{
			dumper.DumpValue{
				Key:   "character_set",
				Value: "latin1",
			},
		},
		[]dumper.DumpValue{},
		"\"error\":\"client is trying to connect using SSL. tcpdp mysql dumper not support SSL connection\"",
	},
}

func TestMysqlReadHandshakeResponse(t *testing.T) {
	tts := newMysqlReadTests()

	for _, tt := range tts {
		fmt.Printf("%#v\n", tt.connMetadata.Internal)
		out := new(bytes.Buffer)
		d := &Dumper{
			logger: newTestLogger(out),
		}
		in := tt.in
		direction := tt.direction
		connMetadata := &tt.connMetadata

		actual := d.readHandshakeResponse(in, direction, connMetadata)
		expected := tt.expected

		if len(actual) != len(expected) {
			t.Errorf("%v\nactual %v\nwant %v", tt.description, actual, expected)
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
	tts := newMysqlReadTests()

	for _, tt := range tts {
		fmt.Printf("%#v\n", tt.connMetadata.Internal)
		out := new(bytes.Buffer)
		d := &Dumper{
			logger: newTestLogger(out),
		}
		in := tt.in
		direction := tt.direction
		connMetadata := &tt.connMetadata

		actual := d.Read(in, direction, connMetadata)
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

func TestMysqlDump(t *testing.T) {
	tts := newMysqlReadTests()

	for _, tt := range tts {
		out := new(bytes.Buffer)
		d := &Dumper{
			logger: newTestLogger(out),
		}
		in := tt.in
		direction := tt.direction
		connMetadata := &tt.connMetadata

		additional := []dumper.DumpValue{}

		err := d.Dump(in, direction, connMetadata, additional)
		if err != nil {
			t.Errorf("%v", err)
		}

		expected := tt.expected

		actual := connMetadata.DumpValues
		if len(actual) != len(expected) {
			t.Errorf("%v\nactual %v\nwant %v", tt.description, actual, expected)
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

		if tt.logContain == "" {
			if log != tt.logContain {
				t.Errorf("%v not be %v", log, tt.logContain)
			}
		} else {
			if !strings.Contains(log, tt.logContain) {
				t.Errorf("%v not be %v", log, tt.logContain)
			}
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
	t        dataType
	expected interface{}
}{
	{
		[]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		typeLonglong,
		int64(1),
	},
	{
		[]byte{0x01, 0x00, 0x00, 0x00},
		typeLong,
		int32(1),
	},
	{
		[]byte{0x01, 0x00, 0x00, 0x00},
		typeInt24,
		int32(1),
	},
	{
		[]byte{0x01, 0x00},
		typeShort,
		int16(1),
	},
	{
		[]byte{0xe2, 0x07},
		typeYear,
		int16(2018),
	},
	{
		[]byte{0x01},
		typeTiny,
		int8(1),
	},
	{
		[]byte{0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x24, 0x40},
		typeDouble,
		10.2,
	},
	{
		[]byte{0x33, 0x33, 0x23, 0x41},
		typeFloat,
		float32(10.2),
	},
	{
		[]byte{0x04, 0xda, 0x07, 0x0a, 0x11},
		typeDate,
		"2010-10-17",
	},
	{
		[]byte{0x0b, 0xda, 0x07, 0x0a, 0x11, 0x13, 0x1b, 0x1e, 0x01, 0x00, 0x00, 0x00},
		typeDatetime,
		"2010-10-17 19:27:30.000 001",
	},
	{
		[]byte{0x0b, 0xda, 0x07, 0x0a, 0x11, 0x13, 0x1b, 0x1e, 0x01, 0x00, 0x00, 0x00},
		typeTimestamp,
		"2010-10-17 19:27:30.000 001",
	},
	{
		[]byte{0x0c, 0x01, 0x78, 0x00, 0x00, 0x00, 0x13, 0x1b, 0x1e, 0x01, 0x00, 0x00, 0x00},
		typeTime,
		"-120d 19:27:30.000 001",
	},
	{
		[]byte{0x08, 0x01, 0x78, 0x00, 0x00, 0x00, 0x13, 0x1b, 0x1e},
		typeTime,
		"-120d 19:27:30",
	},
	{
		[]byte{0x01},
		typeTime,
		"0d 00:00:00",
	},
	{
		[]byte{},
		typeNull,
		nil,
	},
	{
		[]byte{0x03, 0x66, 0x6f, 0x6f},
		typeString,
		"foo",
	},
}

func TestMysqlReadBinaryProtocolValue(t *testing.T) {
	for _, tt := range mysqlBinaryProtocolValueTests {
		buff := bytes.NewBuffer(tt.in)
		actual := readBinaryProtocolValue(buff, tt.t, charSetUnknown)
		if actual != tt.expected {
			t.Errorf("actual %#v\nwant %#v", actual, tt.expected)
		}
	}
}

var readBytesTests = []struct {
	in       []byte
	len      int
	expected []byte
}{
	{
		[]byte{0x12, 0x34, 0x56, 0x78},
		2,
		[]byte{0x12, 0x34},
	},
	{
		[]byte{0x12, 0x34, 0x56, 0x78},
		0,
		[]byte{},
	},
}

func TestReadBytes(t *testing.T) {
	for _, tt := range readBytesTests {
		buff := bytes.NewBuffer(tt.in)
		actual := readBytes(buff, tt.len)
		if !bytes.Equal(actual, tt.expected) {
			t.Errorf("actual %#v\nwant %#v", actual, tt.expected)
		}
	}
}

// newTestLogger return zap.Logger for test
func newTestLogger(out io.Writer) *zap.Logger {
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	logger := zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.AddSync(out),
		zapcore.DebugLevel,
	))

	return logger
}

func newMysqlReadTests() []mysqlReadTest {
	buf := bytes.NewBuffer(nil)
	_ = gob.NewEncoder(buf).Encode(&mysqlReadTests)
	tts := []mysqlReadTest{}
	_ = gob.NewDecoder(buf).Decode(&tts)
	return tts
}
