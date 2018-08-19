package dumper

import (
	"encoding/hex"
	"time"

	"github.com/k1LoW/tcprxy/logger"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// HexDumper ...
type HexDumper struct {
	logger *zap.Logger
}

// NewHexDumper returns a HexDumper
func NewHexDumper() *HexDumper {
	dumper := &HexDumper{
		logger: logger.NewDumpLogger(),
	}
	return dumper
}

// Dump TCP
func (h *HexDumper) Dump(in []byte, kvs []DumpValue) error {
	fields := []zapcore.Field{}
	for _, kv := range kvs {
		fields = append(fields, zap.String(kv.Key, kv.Value))
	}
	fields = append(fields, zap.Time("ts", time.Now()))

	h.logger.Info(hex.Dump(in), fields...)
	return nil
}
