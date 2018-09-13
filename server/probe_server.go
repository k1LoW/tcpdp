package server

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/k1LoW/tcprxy/dumper"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// ProbeServer struct
type ProbeServer struct {
	pidfile    string
	ctx        context.Context
	shutdown   context.CancelFunc
	Wg         *sync.WaitGroup
	ClosedChan chan struct{}
	logger     *zap.Logger
	dumper     dumper.Dumper
}

// NewProbeServer returns a new Server
func NewProbeServer(ctx context.Context, logger *zap.Logger) *ProbeServer {
	innerCtx, shutdown := context.WithCancel(ctx)
	closedChan := make(chan struct{})

	var d dumper.Dumper
	dumpType := viper.GetString("proxy.dumper")

	switch dumpType {
	case "hex":
		d = dumper.NewHexDumper()
	case "pg":
		d = dumper.NewPgDumper()
	case "mysql":
		d = dumper.NewMysqlDumper()
	default:
		d = dumper.NewHexDumper()
	}

	pidfile, err := filepath.Abs(viper.GetString("proxy.pidfile"))
	if err != nil {
		logger.WithOptions(zap.AddCaller()).Fatal("pidfile path error", zap.Error(err))
	}

	return &ProbeServer{
		pidfile:    pidfile,
		ctx:        innerCtx,
		shutdown:   shutdown,
		ClosedChan: closedChan,
		logger:     logger,
		dumper:     d,
	}
}

// Start probe server.
func (s *ProbeServer) Start() error {
	err := s.writePID()
	if err != nil {
		s.logger.WithOptions(zap.AddCaller()).Fatal(fmt.Sprintf("can not write %s", s.pidfile), zap.Error(err))
		return err
	}
	defer s.deletePID()

	defer func() {
		close(s.ClosedChan)
	}()

	device := viper.GetString("probe.interface")
	target := viper.GetString("probe.target")

	tAddr, err := net.ResolveTCPAddr("tcp", target)
	if err != nil {
		s.logger.Fatal("error", zap.Error(err))
		return err
	}
	host := tAddr.IP
	port := tAddr.Port

	snapshot := 0xFFFF
	promiscuous := true
	pValues := []dumper.DumpValue{
		dumper.DumpValue{
			Key:   "interface",
			Value: device,
		},
		dumper.DumpValue{
			Key:   "probe_target_addr",
			Value: target,
		},
	}

	handle, err := pcap.OpenLive(
		device,
		int32(snapshot),
		promiscuous,
		pcap.BlockForever,
	)
	if err != nil {
		s.logger.WithOptions(zap.AddCaller()).Fatal("pcap OpenLive error", zap.Error(err))
		return err
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(fmt.Sprintf("tcp and host %s and port %d", host.String(), port)); err != nil {
		s.logger.WithOptions(zap.AddCaller()).Fatal("BPF Filter error", zap.Error(err))
		return err
	}

	vMap := map[string][]dumper.DumpValue{}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()
	for {
		select {
		case <-s.ctx.Done():
			return nil
		case packet := <-packetChan:
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
			if ip.DstIP.String() == host.String() && uint16(tcp.DstPort) == uint16(port) {
				key = fmt.Sprintf("%s:%d", ip.SrcIP.String(), tcp.SrcPort)
			} else {
				key = fmt.Sprintf("%s:%d", ip.DstIP.String(), tcp.DstPort)
			}
			if tcp.SYN || tcp.FIN {
				// TCP connection start or end
				_, ok := vMap[key]
				if ok {
					delete(vMap, key)
				}
			}

			in := tcpLayer.LayerPayload()
			if len(in) == 0 {
				continue
			}

			v := s.dumper.ReadPersistentValues(in)
			if len(v) > 0 {
				vMap[key] = v
			}

			values := []dumper.DumpValue{
				dumper.DumpValue{
					Key:   "src_addr",
					Value: fmt.Sprintf("%s:%d", ip.SrcIP.String(), tcp.SrcPort),
				},
				dumper.DumpValue{
					Key:   "dst_addr",
					Value: fmt.Sprintf("%s:%d", ip.DstIP.String(), tcp.DstPort),
				},
			}

			read := s.dumper.Read(in)
			if len(read) == 0 {
				continue
			}

			values = append(values, read...)
			values = append(values, pValues...)
			v, ok := vMap[key]
			if ok {
				values = append(values, v...)
			}

			s.dumper.Log(values)

		default:
		}
	}
}

// Shutdown server.
func (s *ProbeServer) Shutdown() {
	s.shutdown()
}

// https://gist.github.com/davidnewhall/3627895a9fc8fa0affbd747183abca39
func (s *ProbeServer) writePID() error {
	if data, err := ioutil.ReadFile(s.pidfile); err == nil {
		if pid, err := strconv.Atoi(string(data)); err == nil {
			if process, err := os.FindProcess(pid); err == nil {
				if err := process.Signal(syscall.Signal(0)); err == nil {
					return fmt.Errorf("pid already running: %d", pid)
				}
			}
		}
	}
	return ioutil.WriteFile(s.pidfile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0664)
}

func (s *ProbeServer) deletePID() {
	if err := os.Remove(s.pidfile); err != nil {
		s.logger.WithOptions(zap.AddCaller()).Fatal(fmt.Sprintf("can not delete %s", s.pidfile), zap.Error(err))
	}
}
