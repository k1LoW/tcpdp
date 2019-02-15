package reader

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/k1LoW/tcpdp/dumper"
)

// https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
// union {
//     struct {
//         char line[108];
//     } v1;
//     struct {
//         uint8_t sig[12];
//         uint8_t ver_cmd;
//         uint8_t fam;
//         uint16_t len;
//         union {
//             struct {  /* for TCP/UDP over IPv4, len = 12 */
//                 uint32_t src_addr;
//                 uint32_t dst_addr;
//                 uint16_t src_port;
//                 uint16_t dst_port;
//             } ip4;
//             struct {  /* for TCP/UDP over IPv6, len = 36 */
//                  uint8_t  src_addr[16];
//                  uint8_t  dst_addr[16];
//                  uint16_t src_port;
//                  uint16_t dst_port;
//             } ip6;
//             struct {  /* for AF_UNIX sockets, len = 216 */
//                  uint8_t src_addr[108];
//                  uint8_t dst_addr[108];
//             } unx;
//         } addr;
//     } v2;
// } hdr;

var (
	v1Prefix = []byte("PROXY")
	v2Prefix = []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}
)

// ParseProxyProtocolHeader ...
func ParseProxyProtocolHeader(in []byte) (int, []dumper.DumpValue, error) {
	if bytes.Index(in, v1Prefix) == 0 {
		return parseProxyProtocolV1Header(in)
	}
	if bytes.Index(in, v2Prefix) == 0 {
		return parseProxyProtocolV2Header(in)
	}
	return 0, []dumper.DumpValue{}, nil
}

func parseProxyProtocolV1Header(in []byte) (int, []dumper.DumpValue, error) {
	idx := bytes.Index(in, []byte("\r\n"))
	values := strings.Split(string(in[0:idx]), " ")
	if len(values) == 6 {
		srcPort, _ := strconv.ParseUint(values[4], 10, 16)
		dstPort, _ := strconv.ParseUint(values[5], 10, 16)
		return idx + 2, []dumper.DumpValue{
			dumper.DumpValue{
				Key:   "proxy_protocol_src_addr",
				Value: fmt.Sprintf("%s:%d", values[2], srcPort),
			},
			dumper.DumpValue{
				Key:   "proxy_protocol_dst_addr",
				Value: fmt.Sprintf("%s:%d", values[3], dstPort),
			},
		}, nil
	}
	return 0, []dumper.DumpValue{}, nil
}

func parseProxyProtocolV2Header(in []byte) (int, []dumper.DumpValue, error) {
	byte13 := in[12]
	if !(0x20 == byte13 || 0x21 == byte13) {
		return 0, []dumper.DumpValue{}, errors.New("unexpected values")
	}
	// PROXY or LOCAL
	byte14 := in[13]
	length := int(binary.BigEndian.Uint16(in[14:16]))
	idx := 16

	if byte14 == 0x00 {
		// UNSPEC
		return idx + length, []dumper.DumpValue{}, errors.New("unexpected values")
	}

	if 0x10 == byte14&0xf0 {
		// IPv4: 12byte
		var (
			srcAddr net.IP // 4
			dstAddr net.IP // 4
			srcPort uint16 // 2
			dstPort uint16 // 2
		)

		srcAddr = in[idx : idx+4]
		idx = idx + 4

		dstAddr = in[idx : idx+4]
		idx = idx + 4

		srcPort = binary.BigEndian.Uint16(in[idx : idx+2])
		idx = idx + 2

		dstPort = binary.BigEndian.Uint16(in[idx : idx+2])
		idx = idx + 2
		return idx, []dumper.DumpValue{
			dumper.DumpValue{
				Key:   "proxy_protocol_src_addr",
				Value: fmt.Sprintf("%s:%d", srcAddr.String(), srcPort),
			},
			dumper.DumpValue{
				Key:   "proxy_protocol_dst_addr",
				Value: fmt.Sprintf("%s:%d", dstAddr.String(), dstPort),
			},
		}, nil
	} else if 0x20 == byte14&0xf0 {
		// IPv6: 36byte
		var (
			srcAddr net.IP // 16
			dstAddr net.IP // 16
			srcPort uint16 // 2
			dstPort uint16 // 2
		)

		srcAddr = in[idx : idx+16]
		idx = idx + 16

		dstAddr = in[idx : idx+16]
		idx = idx + 16

		srcPort = binary.BigEndian.Uint16(in[idx : idx+2])
		idx = idx + 2

		dstPort = binary.BigEndian.Uint16(in[idx : idx+2])
		idx = idx + 2
		return idx, []dumper.DumpValue{
			dumper.DumpValue{
				Key:   "proxy_protocol_src_addr",
				Value: fmt.Sprintf("%s:%d", srcAddr.String(), srcPort),
			},
			dumper.DumpValue{
				Key:   "proxy_protocol_dst_addr",
				Value: fmt.Sprintf("%s:%d", dstAddr.String(), dstPort),
			},
		}, nil
	} else if 0x30 == byte14&0xf0 {
		// AF_UNIX: 216byte
		var (
			srcAddr []byte
			dstAddr []byte
		)

		srcAddr = in[idx : idx+108]
		idx = idx + 108

		dstAddr = in[idx : idx+108]
		idx = idx + 108
		return idx, []dumper.DumpValue{
			dumper.DumpValue{
				Key:   "proxy_protocol_src_addr",
				Value: string(bytes.TrimRight(srcAddr, "\x00")),
			},
			dumper.DumpValue{
				Key:   "proxy_protocol_dst_addr",
				Value: string(bytes.TrimRight(dstAddr, "\x00")),
			},
		}, nil
	}

	return idx + length, []dumper.DumpValue{}, errors.New("unsupported values")
}
