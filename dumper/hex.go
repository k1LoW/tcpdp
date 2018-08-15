package dumper

import (
	"encoding/hex"
	"time"

	"github.com/k1LoW/tcprxy/logger"
	"go.uber.org/zap"
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
func (h *HexDumper) Dump(cid string, in []byte) error {
	h.logger.Info(hex.Dump(in), zap.String("cid", cid), zap.Time("ts", time.Now()))
	return nil
}
