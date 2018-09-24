package reader

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/k1LoW/tcpdp/dumper"
	"github.com/rs/xid"
)

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

// PacketReader struct
type PacketReader struct {
	ctx          context.Context
	packetSource *gopacket.PacketSource
	dumper       dumper.Dumper
	pValues      []dumper.DumpValue
}

// NewPacketReader return PacketReader
func NewPacketReader(ctx context.Context, packetSource *gopacket.PacketSource, dumper dumper.Dumper, pValues []dumper.DumpValue) PacketReader {
	reader := PacketReader{
		ctx:          ctx,
		packetSource: packetSource,
		dumper:       dumper,
		pValues:      pValues,
	}
	return reader
}

// ReadAndDump from gopacket.PacketSource
func (r *PacketReader) ReadAndDump(host string, port uint16) error {
	mMap := map[string]*dumper.ConnMetadata{}

	packetChan := r.packetSource.Packets()
	for {
		select {
		case <-r.ctx.Done():
			return nil
		case packet := <-packetChan:
			if packet == nil {
				return nil
			}
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				continue
			}
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer == nil {
				continue
			}
			ip, _ := ipLayer.(*layers.IPv4)
			tcp, _ := tcpLayer.(*layers.TCP)

			var key string
			var direction dumper.Direction
			srcToDstKey := fmt.Sprintf("%s:%d->%s:%d", ip.SrcIP.String(), tcp.SrcPort, ip.DstIP.String(), tcp.DstPort)
			dstToSrcKey := fmt.Sprintf("%s:%d->%s:%d", ip.DstIP.String(), tcp.DstPort, ip.SrcIP.String(), tcp.SrcPort)
			if (host == "" || ip.DstIP.String() == host) && uint16(tcp.DstPort) == port {
				key = srcToDstKey
				direction = dumper.SrcToDst
			} else if (host == "" || ip.SrcIP.String() == host) && uint16(tcp.SrcPort) == port {
				key = dstToSrcKey
				direction = dumper.DstToSrc
			} else {
				key = "-"
				direction = dumper.Unknown
			}

			if tcp.SYN && !tcp.ACK {
				if direction == dumper.Unknown {
					key = srcToDstKey
				}

				// TCP connection start
				_, ok := mMap[key]
				if ok {
					delete(mMap, key)
				}

				// TCP connection start ( hex, mysql, pg )
				connID := xid.New().String()
				connMetadata := r.dumper.NewConnMetadata()
				connMetadata.DumpValues = []dumper.DumpValue{
					dumper.DumpValue{
						Key:   "conn_id",
						Value: connID,
					},
				}
				mMap[key] = connMetadata

			} else if tcp.SYN && tcp.ACK {
				if direction == dumper.Unknown {
					key = dstToSrcKey
				}

				_, ok := mMap[key]
				if !ok {
					// TCP connection start ( hex, mysql, pg )
					connID := xid.New().String()
					connMetadata := r.dumper.NewConnMetadata()
					connMetadata.DumpValues = []dumper.DumpValue{
						dumper.DumpValue{
							Key:   "conn_id",
							Value: connID,
						},
					}
					mMap[key] = connMetadata
				}

			} else if tcp.FIN {
				// TCP connection end
				_, ok := mMap[key]
				if ok {
					delete(mMap, key)
				}
				if direction == dumper.Unknown {
					for _, key := range []string{srcToDstKey, dstToSrcKey} {
						_, ok := mMap[key]
						if ok {
							delete(mMap, key)
						}
					}
				}
			}

			in := tcpLayer.LayerPayload()
			if len(in) == 0 {
				continue
			}

			if direction == dumper.Unknown {
				for _, k := range []string{srcToDstKey, dstToSrcKey} {
					_, ok := mMap[k]
					if ok {
						key = k
					}
				}
			}

			connMetadata, ok := mMap[key]
			if !ok {
				connMetadata = r.dumper.NewConnMetadata()
			}

			ts := packet.Metadata().CaptureInfo.Timestamp

			values := []dumper.DumpValue{
				dumper.DumpValue{
					Key:   "ts",
					Value: ts,
				},
				dumper.DumpValue{
					Key:   "src_addr",
					Value: fmt.Sprintf("%s:%d", ip.SrcIP.String(), tcp.SrcPort),
				},
				dumper.DumpValue{
					Key:   "dst_addr",
					Value: fmt.Sprintf("%s:%d", ip.DstIP.String(), tcp.DstPort),
				},
			}

			read := r.dumper.Read(in, direction, connMetadata)
			mMap[key] = connMetadata
			if len(read) == 0 {
				continue
			}

			values = append(values, read...)
			values = append(values, r.pValues...)
			values = append(values, connMetadata.DumpValues...)

			r.dumper.Log(values)
		default:
		}
	}
}
