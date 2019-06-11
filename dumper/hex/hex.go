package hex

import (
	"encoding/hex"
	"strings"
	"time"

	"github.com/k1LoW/tcpdp/dumper"
	"github.com/k1LoW/tcpdp/logger"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Dumper ...
type Dumper struct {
	name   string
	logger *zap.Logger
}

// NewDumper returns a Dumper
func NewDumper() *Dumper {
	dumper := &Dumper{
		name:   "hex",
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
	read, err := h.Read(in, direction, connMetadata)
	if err != nil {
		return err
	}
	values = append(values, read...)
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
func (h *Dumper) Read(in []byte, direction dumper.Direction, connMetadata *dumper.ConnMetadata) ([]dumper.DumpValue, error) {
	hexdump := strings.Split(hex.Dump(in), "\n")
	byteString := []string{}
	ascii := []string{}
	for _, hd := range hexdump {
		if hd == "" {
			continue
		}
		byteString = append(byteString, strings.TrimRight(strings.Replace(hd[10:58], "  ", " ", 1), " "))
		ascii = append(ascii, hd[61:len(hd)-1])
	}

	return []dumper.DumpValue{
		dumper.DumpValue{
			Key:   "bytes",
			Value: strings.Join(byteString, " "),
		},
		dumper.DumpValue{
			Key:   "ascii",
			Value: strings.Join(ascii, ""),
		},
	}, nil
}

// Log values
func (h *Dumper) Log(values []dumper.DumpValue) {
	fields := []zapcore.Field{}
	for _, kv := range values {
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
