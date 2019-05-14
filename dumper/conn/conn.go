package conn

import (
	"time"

	"github.com/k1LoW/tcpdp/dumper"
	"github.com/k1LoW/tcpdp/logger"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Dumper struct {
	name   string
	logger *zap.Logger
}

// NewDumper returns a Dumper
func NewDumper() *Dumper {
	dumper := &Dumper{
		name:   "conn",
		logger: logger.NewHexLogger(),
	}
	return dumper
}

// Name return dumper name
func (h *Dumper) Name() string {
	return h.name
}

// Dump TCP
func (h *Dumper) Dump(in []byte, direction dumper.Direction, connMetadata *dumper.ConnMetadata, additional []dumper.DumpValue) error {
	values := []dumper.DumpValue{}
	values = append(values, connMetadata.DumpValues...)
	values = append(values, additional...)
	values = append(values, dumper.DumpValue{
		Key:   "ts",
		Value: time.Now(),
	})

	h.Log(values)
	return nil
}

// Read return byte to analyzed string
func (h *Dumper) Read(in []byte, direction dumper.Direction, connMetadata *dumper.ConnMetadata) []dumper.DumpValue {
	return []dumper.DumpValue{
		dumper.DumpValue{
			Key:   "dummy",
			Value: "dummy",
		},
	}
}

// Log values
func (h *Dumper) Log(values []dumper.DumpValue) {
	fields := []zapcore.Field{}
	for _, kv := range values {
		if kv.Key == "dummy" {
			continue
		}
		fields = append(fields, zap.Any(kv.Key, kv.Value))
	}
	h.logger.Info("-", fields...)
}

// NewConnMetadata ...
func (h *Dumper) NewConnMetadata() *dumper.ConnMetadata {
	return &dumper.ConnMetadata{
		DumpValues: []dumper.DumpValue{},
	}
}
