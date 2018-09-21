package dumper

import (
	"bytes"
	"io"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

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
