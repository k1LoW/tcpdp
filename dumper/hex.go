package dumper

import (
	"encoding/hex"
)

// HexDumper ...
type HexDumper struct{}

// Dump TCP
func (h *HexDumper) Dump(in []byte) (error, string) {
	return nil, hex.Dump(in)
}
