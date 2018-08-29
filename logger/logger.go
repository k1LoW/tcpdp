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

	stdout := viper.GetBool(fmt.Sprintf("%s.stdout", LogTypeLog))
	enable := viper.GetBool(fmt.Sprintf("%s.enable", LogTypeLog))
	format := viper.GetString(fmt.Sprintf("%s.format", LogTypeLog))
	cores := []zapcore.Core{}

	if stdout {
		stdoutCore := zapcore.NewCore(
			zapcore.NewConsoleEncoder(encoderConfig),
			zapcore.AddSync(os.Stdout),
			zapcore.DebugLevel,
		)
		cores = append(cores, stdoutCore)
	}

	if enable {
		w := newLogWriter(LogTypeLog)
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
		cores = append(cores, logCore)
	}

	logger := zap.New(zapcore.NewTee(cores...))

	return logger
}

// NewHexLogger returns logger for hex
func NewHexLogger() *zap.Logger {
	encoderConfig := zapcore.EncoderConfig{
		MessageKey:     "dump",
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	return newDumpLogger(encoderConfig)
}

// NewQueryLogger returns logger for mysql/pg
func NewQueryLogger() *zap.Logger {
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "ts",
		MessageKey:     "query",
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	return newDumpLogger(encoderConfig)
}

func newDumpLogger(encoderConfig zapcore.EncoderConfig) *zap.Logger {
	stdout := viper.GetBool(fmt.Sprintf("%s.stdout", LogTypeDumpLog))
	enable := viper.GetBool(fmt.Sprintf("%s.enable", LogTypeDumpLog))
	format := viper.GetString(fmt.Sprintf("%s.format", LogTypeDumpLog))
	cores := []zapcore.Core{}

	if stdout {
		stdoutCore := zapcore.NewCore(
			zapcore.NewConsoleEncoder(encoderConfig),
			zapcore.AddSync(os.Stdout),
			zapcore.DebugLevel,
		)
		cores = append(cores, stdoutCore)
	}

	if enable {
		w := newLogWriter(LogTypeDumpLog)
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
		cores = append(cores, logCore)
	}

	logger := zap.New(zapcore.NewTee(cores...))

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
