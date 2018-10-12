package reader

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/k1LoW/tcpdp/dumper"
	"go.uber.org/zap"
)

const anyIP = "0.0.0.0"

var maxPacketLen = 0xFFFF // 65535

// ParseTarget parse target to host:port
func ParseTarget(target string) (string, uint16, error) {
	var port uint16
	var host string
	if target == "" {
		host = ""
		port = uint16(0)
	} else if strings.Contains(target, ":") {
		tAddr, err := net.ResolveTCPAddr("tcp", target)
		if err != nil {
			return "", uint16(0), nil
		}
		host = tAddr.IP.String()
		port = uint16(tAddr.Port)
	} else if strings.Contains(target, ".") {
		host = target
		port = uint16(0)
	} else {
		host = ""
		port64, err := strconv.ParseUint(target, 10, 64)
		if err != nil {
			return "", uint16(0), nil
		}
		port = uint16(port64)
	}
	return host, port, nil
}

// NewBPFFilterString return string for BPF
func NewBPFFilterString(host string, port uint16) string {
	f := fmt.Sprintf("tcp and host %s and port %d", host, port)
	if (host == "" || host == anyIP) && port > 0 {
		f = fmt.Sprintf("tcp port %d", port)
	} else if (host != "" && host != anyIP) && port == 0 {
		f = fmt.Sprintf("tcp and host %s", host)
	} else if (host == "" || host == anyIP) && port == 0 {
		f = "tcp"
	}
	return f
}

// PacketReader struct
type PacketReader struct {
	ctx          context.Context
	packetSource *gopacket.PacketSource
	dumper       dumper.Dumper
	pValues      []dumper.DumpValue
	logger       *zap.Logger
}

// NewPacketReader return PacketReader
func NewPacketReader(ctx context.Context, packetSource *gopacket.PacketSource, dumper dumper.Dumper, pValues []dumper.DumpValue, logger *zap.Logger) PacketReader {
	reader := PacketReader{
		ctx:          ctx,
		packetSource: packetSource,
		dumper:       dumper,
		pValues:      pValues,
		logger:       logger,
	}
	return reader
}

// ReadAndDump from gopacket.PacketSource
func (r *PacketReader) ReadAndDump(host string, port uint16) error {
	packetChan := r.packetSource.Packets()
	for {
		select {
		case <-r.ctx.Done():
			return nil
		case <-packetChan:
			// empty logic
			continue
		}
	}
}

func newByteMap() map[dumper.Direction][]byte {
	return map[dumper.Direction][]byte{
		dumper.SrcToDst: []byte{},
		dumper.DstToSrc: []byte{},
		dumper.Unknown:  []byte{},
	}
}
