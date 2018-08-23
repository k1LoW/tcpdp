package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/hnakamur/zap-ltsv"
	"github.com/lestrrat-go/file-rotatelogs"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// LogFormatJSON for format JSON
const LogFormatJSON = "json"

// LogFormatLTSV for format LTSV
const LogFormatLTSV = "ltsv"

// LogTypeLog for tcprxy.log
const LogTypeLog = "log"

// LogTypeDumpLog for dump.log
const LogTypeDumpLog = "dumpLog"

// NewLogger returns logger
func NewLogger() *zap.Logger {
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

	format := viper.GetString(fmt.Sprintf("%s.format", LogTypeLog))
	w := newLogWriter(LogTypeLog)

	consoleCore := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig),
		zapcore.AddSync(os.Stdout),
		zapcore.DebugLevel,
	)

	var encoder zapcore.Encoder
	switch format {
	case LogFormatJSON:
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	case LogFormatLTSV:
		encoder = ltsv.NewLTSVEncoder(encoderConfig)
	}

	logCore := zapcore.NewCore(
		encoder,
		zapcore.AddSync(w),
		zapcore.InfoLevel,
	)

	logger := zap.New(zapcore.NewTee(
		consoleCore,
		logCore,
	))

	return logger
}

// NewDumpLogger returns logger
func NewDumpLogger() *zap.Logger {
	encoderConfig := zapcore.EncoderConfig{
		MessageKey:     "dump",
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	format := viper.GetString(fmt.Sprintf("%s.format", LogTypeLog))
	w := newLogWriter("dumpLog")

	var encoder zapcore.Encoder
	switch format {
	case LogFormatJSON:
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	case LogFormatLTSV:
		encoder = ltsv.NewLTSVEncoder(encoderConfig)
	}

	logCore := zapcore.NewCore(
		encoder,
		zapcore.AddSync(w),
		zapcore.InfoLevel,
	)

	logger := zap.New(logCore)

	return logger
}

// NewQueryLogger returns logger
func NewQueryLogger() *zap.Logger {
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "ts",
		MessageKey:     "query",
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	w := newLogWriter(LogTypeDumpLog)

	logCore := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.AddSync(w),
		zapcore.InfoLevel,
	)

	logger := zap.New(logCore)

	return logger
}

func newLogWriter(logType string) io.Writer {

	dir := viper.GetString(fmt.Sprintf("%s.dir", logType))
	rotateEnable := viper.GetBool(fmt.Sprintf("%s.rotateEnable", logType))
	rotationTime := viper.GetString(fmt.Sprintf("%s.rotationTime", logType))
	rotationCount := uint(viper.GetInt(fmt.Sprintf("%s.rotationCount", logType)))

	var filename string
	switch logType {
	case LogTypeLog:
		filename = "tcprxy.log"
	case LogTypeDumpLog:
		filename = "dump.log"
	}

	path, err := filepath.Abs(fmt.Sprintf("%s/%s", dir, filename))
	if err != nil {
		log.Fatalf("Log setting error %v", err)
	}

	logSuffix := ""
	options := []rotatelogs.Option{
		rotatelogs.WithClock(rotatelogs.Local),
		rotatelogs.WithMaxAge(-1),
	}
	if rotationCount > 0 {
		options = append(options, rotatelogs.WithRotationCount(rotationCount))
	}

	var w io.Writer
	if rotateEnable {
		switch rotationTime {
		case "hourly":
			logSuffix = ".%Y%m%d%H"
			options = append(options, rotatelogs.WithLinkName(path))
		case "daily":
			logSuffix = ".%Y%m%d"
			options = append(options, rotatelogs.WithLinkName(path))
		case "monthly":
			logSuffix = ".%Y%m"
			options = append(options, rotatelogs.WithLinkName(path))
		}
		w, err = rotatelogs.New(
			path+logSuffix,
			options...,
		)
		if err != nil {
			log.Fatalf("Log setting error %v", err)
		}
	} else {
		w, err = os.Open(path)
		if err != nil {
			log.Fatalf("Log setting error %v", err)
		}
	}

	return w
}
