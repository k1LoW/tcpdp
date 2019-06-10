package pg

import (
	"bytes"
	"io"
	"testing"

	"github.com/k1LoW/tcpdp/dumper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var pgValueTests = []struct {
	description   string
	in            []byte
	direction     dumper.Direction
	connMetadata  dumper.ConnMetadata
	expected      []dumper.DumpValue
	expectedQuery []dumper.DumpValue
}{
	{
		"Parse username/database from StartupMessage packet",
		[]byte{
			0x00, 0x00, 0x00, 0x64, 0x00, 0x03, 0x00, 0x00, 0x65, 0x78, 0x74, 0x72, 0x61, 0x5f, 0x66, 0x6c,
			0x6f, 0x61, 0x74, 0x5f, 0x64, 0x69, 0x67, 0x69, 0x74, 0x73, 0x00, 0x32, 0x00, 0x75, 0x73, 0x65,
			0x72, 0x00, 0x70, 0x6f, 0x73, 0x74, 0x67, 0x72, 0x65, 0x73, 0x00, 0x64, 0x61, 0x74, 0x61, 0x62,
			0x61, 0x73, 0x65, 0x00, 0x74, 0x65, 0x73, 0x74, 0x64, 0x62, 0x00, 0x63, 0x6c, 0x69, 0x65, 0x6e,
			0x74, 0x5f, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x00, 0x55, 0x54, 0x46, 0x38, 0x00,
			0x64, 0x61, 0x74, 0x65, 0x73, 0x74, 0x79, 0x6c, 0x65, 0x00, 0x49, 0x53, 0x4f, 0x2c, 0x20, 0x4d,
			0x44, 0x59, 0x00, 0x00,
		},
		dumper.SrcToDst,
		dumper.ConnMetadata{
			DumpValues: []dumper.DumpValue{},
			Internal: connMetadataInternal{
				messageLength: uint32(0),
			},
		},
		[]dumper.DumpValue{
			dumper.DumpValue{
				Key:   "username",
				Value: "postgres",
			},
			dumper.DumpValue{
				Key:   "database",
				Value: "testdb",
			},
		},
		[]dumper.DumpValue{},
	},
	{
		"Parse query from MessageQuery packet",
		[]byte{
			0x51, 0x00, 0x00, 0x00, 0x19, 0x53, 0x45, 0x4c, 0x45, 0x43, 0x54, 0x20, 0x2a, 0x20, 0x46, 0x52,
			0x4f, 0x4d, 0x20, 0x75, 0x73, 0x65, 0x72, 0x73, 0x3b, 0x00,
		},
		dumper.SrcToDst,
		dumper.ConnMetadata{
			DumpValues: []dumper.DumpValue{},
			Internal: connMetadataInternal{
				messageLength: uint32(0),
			},
		},
		[]dumper.DumpValue{},
		[]dumper.DumpValue{
			dumper.DumpValue{
				Key:   "query",
				Value: "SELECT * FROM users;",
			},
			dumper.DumpValue{
				Key:   "message_type",
				Value: "Q",
			},
		},
	},
	{
		"Parse query from MessageParse packet",
		[]byte{
			0x50, 0x00, 0x00, 0x00, 0x34, 0x00, 0x53, 0x45, 0x4c, 0x45, 0x43, 0x54, 0x20, 0x43, 0x4f, 0x4e,
			0x43, 0x41, 0x54, 0x28, 0x24, 0x31, 0x3a, 0x3a, 0x74, 0x65, 0x78, 0x74, 0x2c, 0x20, 0x24, 0x32,
			0x3a, 0x3a, 0x74, 0x65, 0x78, 0x74, 0x2c, 0x20, 0x24, 0x33, 0x3a, 0x3a, 0x74, 0x65, 0x78, 0x74,
			0x29, 0x3b, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00, 0x06, 0x53, 0x00, 0x53, 0x00, 0x00, 0x00,
			0x04,
		},
		dumper.SrcToDst,
		dumper.ConnMetadata{
			DumpValues: []dumper.DumpValue{},
			Internal: connMetadataInternal{
				messageLength: uint32(0),
			},
		},
		[]dumper.DumpValue{},
		[]dumper.DumpValue{
			dumper.DumpValue{
				Key:   "stmt_name",
				Value: "",
			},
			dumper.DumpValue{
				Key:   "parse",
				Value: "SELECT CONCAT($1::text, $2::text, $3::text);",
			},
			dumper.DumpValue{
				Key:   "message_type",
				Value: "P",
			},
		},
	},
	{
		"Parse query from MessageBind packet",
		[]byte{
			0x42, 0x00, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x09, 0x30,
			0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x39, 0x00, 0x00, 0x00, 0x1e, 0xe3, 0x81, 0x82, 0xe3,
			0x81, 0x84, 0xe3, 0x81, 0x86, 0xe3, 0x81, 0x88, 0xe3, 0x81, 0x8a, 0xe3, 0x81, 0x8b, 0xe3, 0x81,
			0x8d, 0xe3, 0x81, 0x8f, 0xe3, 0x81, 0x91, 0xe3, 0x81, 0x93, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x45, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x53, 0x00, 0x00, 0x00, 0x04,
		},
		dumper.SrcToDst,
		dumper.ConnMetadata{
			DumpValues: []dumper.DumpValue{},
			Internal: connMetadataInternal{
				messageLength: uint32(0),
			},
		},
		[]dumper.DumpValue{},
		[]dumper.DumpValue{
			dumper.DumpValue{
				Key:   "portal_name",
				Value: "",
			},
			dumper.DumpValue{
				Key:   "stmt_name",
				Value: "",
			},
			dumper.DumpValue{
				Key:   "bind_values",
				Value: []string{"012345679", "あいうえおかきくけこ", ""},
			},
			dumper.DumpValue{
				Key:   "message_type",
				Value: "B",
			},
		},
	},
	{
		"When direction = dumper.RemoteToClient do not parse query",
		[]byte{
			0x51, 0x00, 0x00, 0x00, 0x19, 0x53, 0x45, 0x4c, 0x45, 0x43, 0x54, 0x20, 0x2a, 0x20, 0x46, 0x52,
			0x4f, 0x4d, 0x20, 0x75, 0x73, 0x65, 0x72, 0x73, 0x3b, 0x00,
		},
		dumper.RemoteToClient,
		dumper.ConnMetadata{
			DumpValues: []dumper.DumpValue{},
			Internal: connMetadataInternal{
				messageLength: uint32(0),
			},
		},
		[]dumper.DumpValue{},
		[]dumper.DumpValue{},
	},
}

func TestPgReadHandshakeStartupMessage(t *testing.T) {
	for _, tt := range pgValueTests {
		t.Run(tt.description, func(t *testing.T) {
			out := new(bytes.Buffer)
			dumper := &Dumper{
				logger: newTestLogger(out),
			}
			in := tt.in
			direction := tt.direction
			connMetadata := &tt.connMetadata

			actual, err := dumper.readHandshake(in, direction, connMetadata)
			if err != nil {
				t.Errorf("%v", err)
			}
			expected := tt.expected

			if len(actual) != len(expected) {
				t.Errorf("actual %v\nwant %v", actual, expected)
			}
			if len(actual) == 2 {
				if actual[0] != expected[0] {
					t.Errorf("actual %v\nwant %v", actual, expected)
				}
				if actual[1] != expected[1] {
					t.Errorf("actual %v\nwant %v", actual, expected)
				}
			}
		})
	}
}

func TestPgRead(t *testing.T) {
	for _, tt := range pgValueTests {
		t.Run(tt.description, func(t *testing.T) {
			out := new(bytes.Buffer)
			dumper := &Dumper{
				logger: newTestLogger(out),
			}
			in := tt.in
			direction := tt.direction
			connMetadata := &tt.connMetadata

			actual, err := dumper.Read(in, direction, connMetadata)
			if err != nil {
				t.Errorf("%v", err)
			}
			expected := tt.expectedQuery

			if len(actual) != len(expected) {
				t.Errorf("actual %v\nwant %v", actual, expected)
			}
			if len(actual) == 2 {
				if actual[0] != expected[0] {
					t.Errorf("actual %#v\nwant %#v", actual[0], expected[0])
				}
				if actual[1] != expected[1] {
					t.Errorf("actual %#v\nwant %#v", actual[1], expected[1])
				}
			}
		})
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
