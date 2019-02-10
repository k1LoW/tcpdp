package reader

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/k1LoW/tcpdp/dumper"
)

var (
	v1Prefix = []byte("PROXY")
	v2Prefix = []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x02}
)

// ParseProxyProtocolHeader ...
func ParseProxyProtocolHeader(in []byte) (int, []dumper.DumpValue, error) {
	if bytes.Index(in, v1Prefix) == 0 {
		return parseProxyProtocolV1Header(in)
	}
	if bytes.Index(in, v2Prefix) == 0 {

	}
	return 0, []dumper.DumpValue{}, nil
}

func parseProxyProtocolV1Header(in []byte) (int, []dumper.DumpValue, error) {
	idx := bytes.Index(in, []byte("\r\n"))
	values := strings.Split(string(in[0:idx]), " ")
	if len(values) == 6 {
		srcPort, _ := strconv.ParseInt(values[4], 10, 64)
		dstPort, _ := strconv.ParseInt(values[5], 10, 64)
		return idx + 2, []dumper.DumpValue{
			dumper.DumpValue{
				Key:   "proxy_protocol_src_addr",
				Value: values[2],
			},
			dumper.DumpValue{
				Key:   "proxy_protocol_dst_addr",
				Value: values[3],
			},
			dumper.DumpValue{
				Key:   "proxy_protocol_src_port",
				Value: srcPort,
			},
			dumper.DumpValue{
				Key:   "proxy_protocol_dst_port",
				Value: dstPort,
			},
		}, nil
	}
	return 0, []dumper.DumpValue{}, nil
}

func parseProxyProtocolV2Header(in []byte) (int, []dumper.DumpValue, error) {
	return 0, []dumper.DumpValue{}, nil
}
