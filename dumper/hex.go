package dumper

import (
	"encoding/hex"
	"time"

	"go.uber.org/zap"
)

// HexDumper ...
type HexDumper struct {
	Logger *zap.Logger
}

// Dump TCP
func (h *HexDumper) Dump(cid string, in []byte) error {
	h.Logger.Info(hex.Dump(in), zap.String("cid", cid), zap.Time("time", time.Now()))
	return nil
}
