package server

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/k1LoW/tcpdp/dumper"
	"github.com/k1LoW/tcpdp/dumper/conn"
	"github.com/k1LoW/tcpdp/dumper/hex"
	"github.com/k1LoW/tcpdp/dumper/mysql"
	"github.com/k1LoW/tcpdp/dumper/pg"
	"github.com/lestrrat-go/server-starter/listener"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Server struct
type Server struct {
	pidfile    string
	listenAddr *net.TCPAddr
	remoteAddr *net.TCPAddr
	ctx        context.Context
	shutdown   context.CancelFunc
	Wg         *sync.WaitGroup
	ClosedChan chan struct{}
	listener   *net.TCPListener
	logger     *zap.Logger
	dumper     dumper.Dumper
}

// NewServer returns a new Server
func NewServer(ctx context.Context, lAddr, rAddr *net.TCPAddr, logger *zap.Logger) *Server {
	innerCtx, shutdown := context.WithCancel(ctx)
	wg := &sync.WaitGroup{}
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
	}

	return &Server{
		pidfile:    pidfile,
		listenAddr: lAddr,
		remoteAddr: rAddr,
		ctx:        innerCtx,
		shutdown:   shutdown,
		Wg:         wg,
		ClosedChan: closedChan,
		logger:     logger,
		dumper:     d,
	}
}

// Start server.
func (s *Server) Start() error {
	err := s.writePID()
	if err != nil {
		s.logger.WithOptions(zap.AddCaller()).Fatal(fmt.Sprintf("can not write %s", s.pidfile), zap.Error(err))
		return err
	}
	defer s.deletePID()
	useServerStarter := viper.GetBool("proxy.useServerStarter")

	if useServerStarter {
		listeners, err := listener.ListenAll()
		if listeners == nil || err != nil {
			s.logger.WithOptions(zap.AddCaller()).Fatal("server-starter listen error", zap.Error(err))
			return err
		}
		lt := listeners[0].(*net.TCPListener)
		s.listener = lt
	} else {
		lt, err := net.ListenTCP("tcp", s.listenAddr)
		if err != nil {
			s.logger.WithOptions(zap.AddCaller()).Fatal("listenAddr ListenTCP error", zap.Error(err))
			return err
		}
		s.listener = lt
	}

	defer func() {
		if err := s.listener.Close(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			s.logger.WithOptions(zap.AddCaller()).Error("server listener Close error", zap.Error(err))
		}
		close(s.ClosedChan)
	}()

	for {
		conn, err := s.listener.AcceptTCP()
		if err != nil {
			if ne, ok := err.(net.Error); ok {
				if ne.Temporary() {
					continue
				}
				if !strings.Contains(err.Error(), "use of closed network connection") {
					select {
					case <-s.ctx.Done():
						break
					default:
						s.logger.WithOptions(zap.AddCaller()).Fatal("listener AcceptTCP error", zap.Error(err))
					}
				}
			}
			return err
		}
		s.Wg.Add(1)
		go s.handleConn(conn)
	}
}

// Shutdown server.
func (s *Server) Shutdown() {
	select {
	case <-s.ctx.Done():
	default:
		s.shutdown()
		if err := s.listener.Close(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			s.logger.WithOptions(zap.AddCaller()).Error("server listener Close error", zap.Error(err))
		}
	}
}

// GracefulShutdown server.
func (s *Server) GracefulShutdown() {
	select {
	case <-s.ctx.Done():
	default:
		if err := s.listener.Close(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			s.logger.WithOptions(zap.AddCaller()).Error("server listener Close error", zap.Error(err))
		}
	}
}

func (s *Server) handleConn(conn *net.TCPConn) {
	defer s.Wg.Done()

	remoteConn, err := net.DialTCP("tcp", nil, s.remoteAddr)
	if err != nil {
		fields := s.fieldsWithErrorAndConn(err, conn)
		s.logger.WithOptions(zap.AddCaller()).Error("remoteAddr DialTCP error", fields...)
		if err := conn.Close(); err != nil {
			s.logger.WithOptions(zap.AddCaller()).Error("server conn Close error", fields...)
		}
		return
	}

	p := NewProxy(s, conn, remoteConn)
	p.Start()
}

func (s *Server) fieldsWithErrorAndConn(err error, conn *net.TCPConn) []zapcore.Field {
	fields := []zapcore.Field{
		zap.Error(err),
		zap.String("client_addr", conn.RemoteAddr().String()),
		zap.String("proxy_listen_addr", conn.LocalAddr().String()),
		zap.String("remote_addr", s.remoteAddr.String()),
	}
	return fields
}

// https://gist.github.com/davidnewhall/3627895a9fc8fa0affbd747183abca39
func (s *Server) writePID() error {
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

func (s *Server) deletePID() {
	if err := os.Remove(s.pidfile); err != nil {
		s.logger.WithOptions(zap.AddCaller()).Fatal(fmt.Sprintf("can not delete %s", s.pidfile), zap.Error(err))
	}
}
