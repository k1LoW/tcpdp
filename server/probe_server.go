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
	"time"

	"code.cloudfoundry.org/bytefmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/k1LoW/tcpdp/dumper"
	"github.com/k1LoW/tcpdp/dumper/hex"
	"github.com/k1LoW/tcpdp/dumper/mysql"
	"github.com/k1LoW/tcpdp/dumper/pg"
	"github.com/k1LoW/tcpdp/reader"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const snaplen = int32(^uint32(0) >> 1)
const promiscuous = true
const timeout = pcap.BlockForever

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
	dumpType := viper.GetString("tcpdp.dumper")

	switch dumpType {
	case "hex":
		d = hex.NewDumper()
	case "pg":
		d = pg.NewDumper()
	case "mysql":
		d = mysql.NewDumper()
	default:
		d = hex.NewDumper()
	}

	pidfile, err := filepath.Abs(viper.GetString("tcpdp.pidfile"))
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
	pcapBufferSize, err := bytefmt.ToBytes(viper.GetString("probe.bufferSize"))
	if err != nil {
		s.logger.WithOptions(zap.AddCaller()).Fatal("parse buffer-size error", zap.Error(err))
		return err
	}

	host, port, err := reader.ParseTarget(target)
	if err != nil {
		s.logger.WithOptions(zap.AddCaller()).Fatal("parse target error", zap.Error(err))
		return err
	}

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

	inactiveHandle, err := pcap.NewInactiveHandle(device)
	if err != nil {
		fields := s.fieldsWithErrorAndValues(err, pValues)
		s.logger.WithOptions(zap.AddCaller()).Fatal("pcap create error", fields...)
		return err
	}
	err = inactiveHandle.SetSnapLen(int(snaplen))
	if err != nil {
		fields := s.fieldsWithErrorAndValues(err, pValues)
		s.logger.WithOptions(zap.AddCaller()).Fatal("pcap create error", fields...)
		return err
	}
	err = inactiveHandle.SetPromisc(promiscuous)
	if err != nil {
		fields := s.fieldsWithErrorAndValues(err, pValues)
		s.logger.WithOptions(zap.AddCaller()).Fatal("pcap create error", fields...)
		return err
	}
	err = inactiveHandle.SetTimeout(timeout)
	if err != nil {
		fields := s.fieldsWithErrorAndValues(err, pValues)
		s.logger.WithOptions(zap.AddCaller()).Fatal("pcap create error", fields...)
		return err
	}
	err = inactiveHandle.SetBufferSize(int(pcapBufferSize))
	if err != nil {
		fields := s.fieldsWithErrorAndValues(err, pValues)
		s.logger.WithOptions(zap.AddCaller()).Fatal("pcap create error", fields...)
		return err
	}

	handle, err := inactiveHandle.Activate()
	if err != nil {
		fields := s.fieldsWithErrorAndValues(err, pValues)
		s.logger.WithOptions(zap.AddCaller()).Fatal("pcap create error", fields...)
		return err
	}

	s.checkStats(handle)
	defer func() {
		stats, _ := handle.Stats()
		s.logger.Info("pcap Stats", zap.Int("packet_received", stats.PacketsReceived), zap.Int("packet_dropped", stats.PacketsDropped), zap.Int("packet_if_dropped", stats.PacketsIfDropped))
		handle.Close()
	}()

	f := reader.NewBPFFilterString(host, port)

	if err := handle.SetBPFFilter(f); err != nil {
		fields := s.fieldsWithErrorAndValues(err, pValues)
		s.logger.WithOptions(zap.AddCaller()).Fatal("BPF error", fields...)
		return err
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	r := reader.NewPacketReader(
		s.ctx,
		packetSource,
		s.dumper,
		pValues,
		s.logger,
	)

	err = r.ReadAndDump(host, port)
	if err != nil {
		fields := s.fieldsWithErrorAndValues(err, pValues)
		s.logger.WithOptions(zap.AddCaller()).Fatal("ReadAndDump error", fields...)
		return err
	}
	return err
}

// Shutdown server.
func (s *ProbeServer) Shutdown() {
	s.shutdown()
}

func (s *ProbeServer) checkStats(handle *pcap.Handle) {
	go func() {
		t := time.NewTicker(60 * time.Second)
		packetsDropped := 0
		packetsIfDropped := 0
	L:
		for {
			select {
			case <-s.ctx.Done():
				break L
			case <-t.C:
				stats, _ := handle.Stats()
				if stats.PacketsDropped > packetsDropped || stats.PacketsIfDropped > packetsIfDropped {
					s.logger.Error("pcap packets dropped", zap.Int("packet_received", stats.PacketsReceived), zap.Int("packet_dropped", stats.PacketsDropped), zap.Int("packet_if_dropped", stats.PacketsIfDropped))
				}
				packetsDropped = stats.PacketsDropped
				packetsIfDropped = stats.PacketsIfDropped
			}
		}
		t.Stop()
	}()
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

func (s *ProbeServer) fieldsWithErrorAndValues(err error, pValues []dumper.DumpValue) []zapcore.Field {
	fields := []zapcore.Field{
		zap.Error(err),
	}

	for _, kv := range pValues {
		fields = append(fields, zap.Any(kv.Key, kv.Value))
	}

	return fields
}
