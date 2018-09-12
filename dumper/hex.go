package dumper

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/k1LoW/tcprxy/logger"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// HexDumper ...
type HexDumper struct {
	name   string
	logger *zap.Logger
}

// NewHexDumper returns a HexDumper
func NewHexDumper() *HexDumper {
	dumper := &HexDumper{
		name:   "hex",
		logger: logger.NewHexLogger(),
	}
	return dumper
}

// Name return dumper name
func (h *HexDumper) Name() string {
	return h.name
}

// Dump TCP
func (h *HexDumper) Dump(in []byte, direction Direction, persistent *DumpValues, additional []DumpValue) error {
	fields := []zapcore.Field{}
	for _, kv := range persistent.Values {
		fields = append(fields, zap.Any(kv.Key, kv.Value))
	}
	for _, kv := range additional {
		fields = append(fields, zap.Any(kv.Key, kv.Value))
	}
	fields = append(fields, zap.Time("ts", time.Now()))

	values := h.Read(in)
	for _, kv := range values {
		fields = append(fields, zap.Any(kv.Key, kv.Value))
	}

	fmt.Printf("%s\n", values[0].Value) // FIXME: Easy to Read

	h.logger.Info("-", fields...)
	return nil
}

// Read return byte to analyzed string
func (h *HexDumper) Read(in []byte) []DumpValue {
	return []DumpValue{
		DumpValue{
			Key:   "dump",
			Value: hex.Dump(in),
		},
	}
}
