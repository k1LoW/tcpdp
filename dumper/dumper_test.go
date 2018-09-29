package dumper

import (
	"io"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

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
