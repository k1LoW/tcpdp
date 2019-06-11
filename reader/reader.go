package reader

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/k1LoW/tcpdp/dumper"
	"github.com/rs/xid"
	"go.uber.org/zap"
)

const anyIP = "0.0.0.0"

var packetTTL = 600       // second
var maxPacketLen = 0xFFFF // 65535

// Target struct
type Target struct {
	TargetHosts []TargetHost
}

// TargetHost struct
type TargetHost struct {
	Host string
	Port uint16
}

// Match return true if TargetHost match
func (t Target) Match(host string, port uint16) bool {
	for _, h := range t.TargetHosts {
		if (h.Host == "" || h.Host == host) && h.Port == port {
			return true
		}
	}
	return false
}

// ParseTarget parse target to host:port
func ParseTarget(t string) (Target, error) {
	ts := strings.Split(strings.Replace(t, " ", "", -1), "||")
	targets := []TargetHost{}
	for _, t := range ts {
		var port uint16
		var host string
		if t == "" {
			host = ""
			port = uint16(0)
		} else if strings.Contains(t, ":") {
			tAddr, err := net.ResolveTCPAddr("tcp", t)
			if err != nil {
				return Target{}, err
			}
			host = tAddr.IP.String()
			port = uint16(tAddr.Port)
		} else if strings.Contains(t, ".") {
			host = t
			port = uint16(0)
		} else {
			host = ""
			port64, err := strconv.ParseUint(t, 10, 64)
			if err != nil {
				return Target{}, err
			}
			port = uint16(port64)
		}
		targets = append(targets, TargetHost{
			Host: host,
			Port: port,
		})
	}
	return Target{
		TargetHosts: targets,
	}, nil
}

// NewBPFFilterString return string for BPF
func NewBPFFilterString(target Target) string {
	targets := target.TargetHosts
	fs := []string{}
	for _, target := range targets {
		host := target.Host
		port := target.Port
		f := fmt.Sprintf("(host %s and port %d)", host, port)
		if (host == "" || host == anyIP) && port > 0 {
			f = fmt.Sprintf("(port %d)", port)
		} else if (host != "" && host != anyIP) && port == 0 {
			f = fmt.Sprintf("(host %s)", host)
		} else if (host == "" || host == anyIP) && port == 0 {
			return "tcp"
		}
		fs = append(fs, f)
	}

	return fmt.Sprintf("tcp and (%s)", strings.Join(fs, " or "))
}

// PacketReader struct
type PacketReader struct {
	ctx            context.Context
	cancel         context.CancelFunc
	packetSource   *gopacket.PacketSource
	dumper         dumper.Dumper
	pValues        []dumper.DumpValue
	logger         *zap.Logger
	packetBuffer   chan gopacket.Packet
	proxyProtocol  bool
	enableInternal bool
}

// NewPacketReader return PacketReader
func NewPacketReader(
	ctx context.Context,
	cancel context.CancelFunc,
	packetSource *gopacket.PacketSource,
	dumper dumper.Dumper,
	pValues []dumper.DumpValue,
	logger *zap.Logger,
	internalBufferLength int,
	proxyProtocol bool,
	enableInternal bool,
) PacketReader {
	internalPacketBuffer := make(chan gopacket.Packet, internalBufferLength)

	reader := PacketReader{
		ctx:            ctx,
		cancel:         cancel,
		packetSource:   packetSource,
		dumper:         dumper,
		pValues:        pValues,
		logger:         logger,
		packetBuffer:   internalPacketBuffer,
		proxyProtocol:  proxyProtocol,
		enableInternal: enableInternal,
	}

	return reader
}

// ReadAndDump from gopacket.PacketSource
func (r *PacketReader) ReadAndDump(target Target) error {
	packetChan := r.packetSource.Packets()

	if r.dumper.Name() == "conn" {
		go r.handleConn(target)
	} else {
		go r.handlePacket(target)
	}
	go r.checkBufferdPacket(packetChan)

	for {
		select {
		case <-r.ctx.Done():
			return nil
		case packet := <-packetChan:
			r.packetBuffer <- packet
		}
	}
}

func (r *PacketReader) handlePacket(target Target) error {
	innerCtx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	mMap := map[string]*dumper.ConnMetadata{} // metadata map per connection
	mssMap := map[string]int{}                // TCP MSS map per connection
	pMap := newPayloadBufferManager()         // long payload map per direction
	var mem runtime.MemStats

	go pMap.startPurgeTicker(innerCtx, r.logger)

	if r.enableInternal {
		go func() {
			t := time.NewTicker(1 * time.Minute)
			for {
				select {
				case <-innerCtx.Done():
					return
				case <-t.C:
					runtime.ReadMemStats(&mem)
					bSize := 0
					pMap.lock()
					for _, b := range pMap.buffers {
						bSize = bSize + b.Size()
					}
					pMap.unlock()

					r.logger.Info("tcpdp internal stats",
						zap.Uint64("tcpdp Alloc", mem.Alloc),
						zap.Uint64("tcpdp TotalAlloc", mem.TotalAlloc),
						zap.Uint64("tcpdp Sys", mem.Sys),
						zap.Uint64("tcpdp Lookups", mem.Lookups),
						zap.Uint64("tcpdp Frees", mem.Frees),
						zap.Uint64("tcpdp HeapAlloc", mem.HeapAlloc),
						zap.Uint64("tcpdp HeapSys", mem.HeapSys),
						zap.Uint64("tcpdp HeapIdle", mem.HeapIdle),
						zap.Uint64("tcpdp HeapInuse", mem.HeapInuse),
						zap.Uint64("tcpdp HeapReleased", mem.HeapReleased),
						zap.Uint64("tcpdp HeapObjects", mem.HeapObjects),
						zap.Uint64("tcpdp StackInuse", mem.StackInuse),
						zap.Uint64("tcpdp StackSys", mem.StackSys),
						zap.Int("packet handler metadata cache (mMap) length", len(mMap)),
						zap.Int("packet handler TCP MSS cache (mssMap) length", len(mssMap)),
						zap.Int("packet handler payload buffer cache (pMap) length", len(pMap.buffers)),
						zap.Int("packet handler payload buffer cache (pMap) size", bSize))
				}
			}
		}()
	}

	for {
		select {
		case <-r.ctx.Done():
			return nil
		case packet := <-r.packetBuffer:
			if packet == nil {
				r.cancel()
				r.logger.WithOptions(zap.AddCaller()).Fatal("null packet")
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
			if target.Match(ip.DstIP.String(), uint16(tcp.DstPort)) {
				key = srcToDstKey
				direction = dumper.SrcToDst
			} else if target.Match(ip.SrcIP.String(), uint16(tcp.SrcPort)) {
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
				delete(mMap, key)
				delete(mssMap, key)
				pMap.deleteBuffer(key)

				// TCP connection start ( hex, mysql, pg )
				connID := xid.New().String()
				mss := int(binary.BigEndian.Uint16(tcp.LayerContents()[22:24]))
				connMetadata := r.dumper.NewConnMetadata()
				connMetadata.DumpValues = []dumper.DumpValue{
					dumper.DumpValue{
						Key:   "conn_id",
						Value: connID,
					},
				}
				mMap[key] = connMetadata
				mssMap[key] = mss
				pMap.newBuffer(key)
			} else if tcp.SYN && tcp.ACK {
				if direction == dumper.Unknown {
					key = dstToSrcKey
				}

				if _, ok := mMap[key]; !ok {
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

				mss := int(binary.BigEndian.Uint16(tcp.LayerContents()[22:24]))
				current, ok := mssMap[key]
				if !ok || mss < current {
					mssMap[key] = mss
				}
				mMap[key].DumpValues = append(mMap[key].DumpValues, dumper.DumpValue{
					Key:   "mss",
					Value: mss,
				})
			} else if tcp.FIN {
				// TCP connection end
				delete(mMap, key)
				delete(mssMap, key)
				pMap.deleteBuffer(key)
				if direction == dumper.Unknown {
					for _, key := range []string{srcToDstKey, dstToSrcKey} {
						delete(mMap, key)
					}
				}
			}

			in := tcpLayer.LayerPayload()
			if len(in) == 0 {
				continue
			}

			if _, ok := pMap.buffers[key]; !ok {
				pMap.newBuffer(key)
			}

			mss, ok := mssMap[key]
			if ok {
				maxPacketLen = mss - (len(tcp.LayerContents()) - 20)
			}
			if len(in) == maxPacketLen {
				pMap.lock()
				pMap.buffers[key].Append(direction, in)
				pMap.unlock()
				continue
			}
			pMap.lock()
			bb := pMap.buffers[key].Get(direction)
			if len(bb) > 0 {
				in = append(bb, in...)
			}
			pMap.buffers[key].Delete(direction)
			pMap.unlock()

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

			var read []dumper.DumpValue
			var err error
			if r.proxyProtocol {
				seek, ppValues, err := ParseProxyProtocolHeader(in)
				if err != nil {
					r.cancel()
					r.logger.WithOptions(zap.AddCaller()).Fatal("error", zap.Error(err))
					return err
				}
				connMetadata.DumpValues = append(connMetadata.DumpValues, ppValues...)
				read, err = r.dumper.Read(in[seek:], direction, connMetadata)
				if err != nil {
					r.logger.WithOptions(zap.AddCaller()).Warn("-", zap.Error(err))
					delete(mMap, key)
					delete(mssMap, key)
					pMap.deleteBuffer(key)
					continue
				}
			} else {
				read, err = r.dumper.Read(in, direction, connMetadata)
				if err != nil {
					// clear
					delete(mMap, key)
					delete(mssMap, key)
					pMap.deleteBuffer(key)
					// error but continue
					continue
				}
			}
			mMap[key] = connMetadata
			if len(read) == 0 {
				continue
			}

			values = append(values, read...)
			values = append(values, r.pValues...)
			values = append(values, connMetadata.DumpValues...)

			r.dumper.Log(values)
		}
	}
}

func (r *PacketReader) handleConn(target Target) error {
	innerCtx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	var mem runtime.MemStats

	if r.enableInternal {
		go func() {
			t := time.NewTicker(1 * time.Minute)
			for {
				select {
				case <-innerCtx.Done():
					return
				case <-t.C:
					runtime.ReadMemStats(&mem)
					r.logger.Info("tcpdp internal stats",
						zap.Uint64("tcpdp Alloc", mem.Alloc),
						zap.Uint64("tcpdp TotalAlloc", mem.TotalAlloc),
						zap.Uint64("tcpdp Sys", mem.Sys),
						zap.Uint64("tcpdp Lookups", mem.Lookups),
						zap.Uint64("tcpdp Frees", mem.Frees),
						zap.Uint64("tcpdp HeapAlloc", mem.HeapAlloc),
						zap.Uint64("tcpdp HeapSys", mem.HeapSys),
						zap.Uint64("tcpdp HeapIdle", mem.HeapIdle),
						zap.Uint64("tcpdp HeapInuse", mem.HeapInuse),
						zap.Uint64("tcpdp HeapReleased", mem.HeapReleased),
						zap.Uint64("tcpdp HeapObjects", mem.HeapObjects),
						zap.Uint64("tcpdp StackInuse", mem.StackInuse),
						zap.Uint64("tcpdp StackSys", mem.StackSys),
					)
				}
			}
		}()
	}

	for {
		select {
		case <-r.ctx.Done():
			return nil
		case packet := <-r.packetBuffer:
			if packet == nil {
				r.cancel()
				r.logger.WithOptions(zap.AddCaller()).Fatal("null packet")
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

			if !(tcp.SYN && !tcp.ACK) {
				continue
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
			in := tcpLayer.LayerPayload()
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

			if r.proxyProtocol {
				_, ppValues, err := ParseProxyProtocolHeader(in)
				if err != nil {
					r.cancel()
					r.logger.WithOptions(zap.AddCaller()).Fatal("error", zap.Error(err))
					return err
				}
				connMetadata.DumpValues = append(connMetadata.DumpValues, ppValues...)
			}
			values = append(values, r.pValues...)
			values = append(values, connMetadata.DumpValues...)

			r.dumper.Log(values)
		}
	}
}

func (r *PacketReader) checkBufferdPacket(packetChan chan gopacket.Packet) {
	t := time.NewTicker(1 * time.Second)
L:
	for {
		select {
		case <-r.ctx.Done():
			break L
		case <-t.C:
			packetBuffered := len(packetChan)
			internalPacketBuffered := len(r.packetBuffer)
			if internalPacketBuffered > (cap(r.packetBuffer)/10) || packetBuffered > (cap(packetChan)/10) {
				r.logger.Info("buffered packet stats", zap.Int("internal_buffered", internalPacketBuffered), zap.Int("packet_buffered", packetBuffered))
			}
		}
	}
	t.Stop()
}
