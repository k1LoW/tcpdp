package dumper

import (
	"encoding/hex"
)

// HexDumper ...
type HexDumper struct{}

// Dump TCP
func (h *HexDumper) Dump(in []byte) (string, error) {
	return hex.Dump(in), nil
}
