package dumper

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/k1LoW/tcpdp/logger"
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
	values := []DumpValue{}
	read := h.Read(in, direction)
	values = append(values, read...)
	values = append(values, persistent.Values...)
	values = append(values, additional...)
	values = append(values, DumpValue{
		Key:   "ts",
		Value: time.Now(),
	})

	fmt.Printf("%s\n", read[0].Value) // FIXME: Easy to Read

	h.Log(values)
	return nil
}

// Read return byte to analyzed string
func (h *HexDumper) Read(in []byte, direction Direction) []DumpValue {
	return []DumpValue{
		DumpValue{
			Key:   "dump",
			Value: hex.Dump(in),
		},
	}
}

// ReadPersistentValues return persistent value each session
func (h *HexDumper) ReadPersistentValues(in []byte) []DumpValue {
	return []DumpValue{}
}

// Log values
func (h *HexDumper) Log(values []DumpValue) {
	fields := []zapcore.Field{}
	for _, kv := range values {
		fields = append(fields, zap.Any(kv.Key, kv.Value))
	}
	h.logger.Info("-", fields...)
}
