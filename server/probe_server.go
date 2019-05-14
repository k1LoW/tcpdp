package server

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"time"

	"code.cloudfoundry.org/bytefmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/k1LoW/tcpdp/dumper"
	"github.com/k1LoW/tcpdp/dumper/conn"
	"github.com/k1LoW/tcpdp/dumper/hex"
	"github.com/k1LoW/tcpdp/dumper/mysql"
	"github.com/k1LoW/tcpdp/dumper/pg"
	"github.com/k1LoW/tcpdp/reader"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var numberRegexp = regexp.MustCompile(`^\d+$`)

const promiscuous = false
const timeout = pcap.BlockForever

// PcapConfig struct
type PcapConfig struct {
	Device         string
	BufferSize     string
	ImmediateMode  bool
	SnapshotLength string
	Promiscuous    bool
	Timeout        time.Duration
	Filter         string
}

// ProbeServer struct
type ProbeServer struct {
	pidfile       string
	ctx           context.Context
	shutdown      context.CancelFunc
	Wg            *sync.WaitGroup
	ClosedChan    chan struct{}
	logger        *zap.Logger
	dumper        dumper.Dumper
	target        reader.Target
	pcapConfig    PcapConfig
	proxyProtocol bool
}

// NewProbeServer returns a new Server
func NewProbeServer(ctx context.Context, logger *zap.Logger) (*ProbeServer, error) {
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
	case "conn":
		d = conn.NewDumper()
	default:
		d = hex.NewDumper()
	}

	pidfile, err := filepath.Abs(viper.GetString("tcpdp.pidfile"))
	if err != nil {
		logger.WithOptions(zap.AddCaller()).Fatal("pidfile path error", zap.Error(err))
		shutdown()
		return nil, err
	}

	target := viper.GetString("probe.target")
	t, err := reader.ParseTarget(target)
	if err != nil {
		logger.WithOptions(zap.AddCaller()).Fatal("parse target error", zap.Error(err))
		shutdown()
		return nil, err
	}

	filter := viper.GetString("probe.filter")
	if filter == "" {
		filter = reader.NewBPFFilterString(t)
	} else {
		filter = fmt.Sprintf("tcp and (%s)", filter)
	}

	pcapConfig := PcapConfig{
		Device:         viper.GetString("probe.interface"),
		BufferSize:     viper.GetString("probe.bufferSize"),
		ImmediateMode:  viper.GetBool("probe.immediateMode"),
		SnapshotLength: viper.GetString("probe.snapshotLength"),
		Promiscuous:    promiscuous,
		Timeout:        timeout,
		Filter:         filter,
	}

	return &ProbeServer{
		pidfile:       pidfile,
		ctx:           innerCtx,
		shutdown:      shutdown,
		ClosedChan:    closedChan,
		logger:        logger,
		dumper:        d,
		target:        t,
		pcapConfig:    pcapConfig,
		proxyProtocol: viper.GetBool("tcpdp.proxyProtocol"),
	}, nil
}

// Start probe server.
func (s *ProbeServer) Start() error {
	if err := s.writePID(); err != nil {
		s.logger.WithOptions(zap.AddCaller()).Fatal(fmt.Sprintf("can not write %s", s.pidfile), zap.Error(err))
		return err
	}
	defer s.deletePID()

	defer func() {
		close(s.ClosedChan)
	}()

	pcapBufferSize, err := byteFormat(s.pcapConfig.BufferSize)
	if err != nil {
		s.logger.WithOptions(zap.AddCaller()).Fatal("parse buffer-size error", zap.Error(err))
		return err
	}
	immediateMode := s.pcapConfig.ImmediateMode
	snapshotLength, err := byteFormat(s.pcapConfig.SnapshotLength)
	if err != nil {
		s.logger.WithOptions(zap.AddCaller()).Fatal("parse snapshot-length error", zap.Error(err))
		return err
	}
	internalBufferLength := viper.GetInt("probe.internalBufferLength")

	target := viper.GetString("probe.target")

	pValues := []dumper.DumpValue{
		dumper.DumpValue{
			Key:   "interface",
			Value: s.pcapConfig.Device,
		},
		dumper.DumpValue{
			Key:   "probe_target_addr",
			Value: target,
		},
	}

	inactiveHandle, err := pcap.NewInactiveHandle(s.pcapConfig.Device)
	if err != nil {
		fields := s.fieldsWithErrorAndValues(err, pValues)
		s.logger.WithOptions(zap.AddCaller()).Fatal("pcap create error", fields...)
		return err
	}
	if err := inactiveHandle.SetSnapLen(int(snapshotLength)); err != nil {
		fields := s.fieldsWithErrorAndValues(err, pValues)
		s.logger.WithOptions(zap.AddCaller()).Fatal("pcap create error (snaplen)", fields...)
		return err
	}
	if err := inactiveHandle.SetPromisc(s.pcapConfig.Promiscuous); err != nil {
		fields := s.fieldsWithErrorAndValues(err, pValues)
		s.logger.WithOptions(zap.AddCaller()).Fatal("pcap create error (promiscuous)", fields...)
		return err
	}
	if err := inactiveHandle.SetTimeout(s.pcapConfig.Timeout); err != nil {
		fields := s.fieldsWithErrorAndValues(err, pValues)
		s.logger.WithOptions(zap.AddCaller()).Fatal("pcap create error (timeout)", fields...)
		return err
	}
	if err := inactiveHandle.SetBufferSize(int(pcapBufferSize)); err != nil {
		fields := s.fieldsWithErrorAndValues(err, pValues)
		s.logger.WithOptions(zap.AddCaller()).Fatal("pcap create error (pcap_buffer_size)", fields...)
		return err
	}
	if err := inactiveHandle.SetImmediateMode(immediateMode); err != nil {
		fields := s.fieldsWithErrorAndValues(err, pValues)
		s.logger.WithOptions(zap.AddCaller()).Fatal("pcap create error (pcap_set_immediate_mode)", fields...)
		return err
	}

	handle, err := inactiveHandle.Activate()
	if err != nil {
		fields := s.fieldsWithErrorAndValues(err, pValues)
		s.logger.WithOptions(zap.AddCaller()).Fatal("pcap handle activate error", fields...)
		return err
	}

	s.checkStats(handle)
	defer func() {
		stats, _ := handle.Stats()
		s.logger.Info("pcap Stats", zap.Int("packet_received", stats.PacketsReceived), zap.Int("packet_dropped", stats.PacketsDropped), zap.Int("packet_if_dropped", stats.PacketsIfDropped))
		handle.Close()
	}()

	if err := handle.SetBPFFilter(s.pcapConfig.Filter); err != nil {
		fields := s.fieldsWithErrorAndValues(err, pValues)
		s.logger.WithOptions(zap.AddCaller()).Fatal("Set BPF error", fields...)
		return err
	}

	proxyProtocol := viper.GetBool("tcpdp.proxyProtocol")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	r := reader.NewPacketReader(
		s.ctx,
		s.shutdown,
		packetSource,
		s.dumper,
		pValues,
		s.logger,
		internalBufferLength,
		proxyProtocol,
	)

	if err := r.ReadAndDump(s.target); err != nil {
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
		t := time.NewTicker(1 * time.Second)
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

// PcapConfig return ProbeServer.pcapConfig
func (s *ProbeServer) PcapConfig() PcapConfig {
	return s.pcapConfig
}

func byteFormat(s string) (int, error) {
	if numberRegexp.MatchString(s) {
		s = s + "B"
	}
	i, err := bytefmt.ToBytes(s)
	if err != nil {
		return -1, err
	}
	return int(i), nil
}
