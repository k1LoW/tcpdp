package reader

import (
	"github.com/k1LoW/tcpdp/dumper"
)

var (
	v1Prefix = []byte("PROXY")
	v2Prefix = []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x02}
)

// ParseProxyProtocolHeader ...
func ParseProxyProtocolHeader(in []byte) (int, []dumper.DumpValue, error) {
	return 0, []dumper.DumpValue{}, nil
}
