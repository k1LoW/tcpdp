package dumper

import (
	"encoding/hex"
)

// HexDumper ...
type HexDumper struct{}

// Dump ...
func (h *HexDumper) Dump(in []byte) string {
	return hex.Dump(in)
}
