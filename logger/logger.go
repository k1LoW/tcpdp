package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	ltsv "github.com/hnakamur/zap-ltsv"
	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// LogFormatJSON for format JSON
const LogFormatJSON = "json"

// LogFormatLTSV for format LTSV
const LogFormatLTSV = "ltsv"

// LogTypeLog for tcpdp.log
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
	stdoutFormat := viper.GetString(fmt.Sprintf("%s.stdoutFormat", LogTypeDumpLog))
	cores := []zapcore.Core{}

	if stdout {
		var encoder zapcore.Encoder
		switch stdoutFormat {
		case LogFormatJSON:
			encoder = zapcore.NewJSONEncoder(encoderConfig)
		case LogFormatLTSV:
			encoder = ltsv.NewLTSVEncoder(encoderConfig)
		default:
			encoder = zapcore.NewConsoleEncoder(encoderConfig)
		}
		stdoutCore := zapcore.NewCore(
			encoder,
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
	rotationHook := viper.GetString(fmt.Sprintf("%s.rotationHook", logType))
	fileName := viper.GetString(fmt.Sprintf("%s.fileName", logType))

	path, err := filepath.Abs(fmt.Sprintf("%s/%s", dir, fileName))
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

	if rotationHook != "" {
		options = append(options, rotatelogs.WithHandler(NewRotateHandler(rotationHook)))
	}
	var w io.Writer
	var t time.Duration
	if rotateEnable {
		switch rotationTime {
		case "minutely":
			logSuffix = ".%Y%m%d%H%M"
			t = 1 * time.Minute
		case "hourly":
			logSuffix = ".%Y%m%d%H"
			t = 1 * time.Hour
		case "daily":
			logSuffix = ".%Y%m%d"
			t = 24 * time.Hour
		default:
			log.Fatal("Log setting error, please specify one of the periods [daily, hourly, minutely]")
		}
		options = append(options, rotatelogs.WithLinkName(path))
		options = append(options, rotatelogs.WithRotationTime(t))
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

// NewRotateHandler return RotateHandler
func NewRotateHandler(c string) *RotateHandler {
	return &RotateHandler{
		command: c,
	}
}

// RotateHandler struct
type RotateHandler struct {
	command string
}

// Handle rotatelogs.Event
func (r *RotateHandler) Handle(e rotatelogs.Event) {
	if e.Type() == rotatelogs.FileRotatedEventType {
		fre := e.(*rotatelogs.FileRotatedEvent)
		out, err := exec.Command(r.command, fre.PreviousFile(), fre.CurrentFile()).CombinedOutput()
		if err != nil {
			log.Printf("Log lotate event error %v\n", err)
		} else {
			log.Printf("Log lotate event success %v\n", out)
		}
	}
}
