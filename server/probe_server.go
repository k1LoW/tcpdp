package server

import (
	"context"
	"fmt"
	"io/ioutil"
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

	device := "lo0"
	snapshot := 0xFFFF
	promiscuous := true
	dumpValues := &dumper.DumpValues{
		Values: []dumper.DumpValue{
			dumper.DumpValue{
				Key:   "device",
				Value: device,
			},
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

	if err := handle.SetBPFFilter("tcp port 33306"); err != nil {
		s.logger.WithOptions(zap.AddCaller()).Fatal("BPF Filter error", zap.Error(err))
		return err
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()
	for {
		select {
		case <-s.ctx.Done():
			return nil
		case packet := <-packetChan:
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				if len(tcpLayer.LayerPayload()) == 0 {
					continue
				}
				in := tcpLayer.LayerPayload()
				err = s.dumper.Dump(in, dumper.ClientToRemote, dumpValues, []dumper.DumpValue{})
				if err != nil {
					s.logger.WithOptions(zap.AddCaller()).Error("dumber Dump error", zap.Error(err))
					return nil
				}
			}
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
