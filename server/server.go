package server

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/k1LoW/tcprxy/dumper"
	l "github.com/k1LoW/tcprxy/logger"
	"github.com/lestrrat-go/server-starter/listener"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// Server struct
type Server struct {
	listenAddr *net.TCPAddr
	remoteAddr *net.TCPAddr
	ctx        context.Context
	shutdown   context.CancelFunc
	Wg         *sync.WaitGroup
	ClosedChan chan struct{}
	listener   *net.TCPListener
	logger     *zap.Logger
	Dumper     dumper.Dumper
}

// NewServer returns a new Server
func NewServer(ctx context.Context, lAddr, rAddr *net.TCPAddr, logger *zap.Logger) *Server {
	innerCtx, shutdown := context.WithCancel(ctx)
	wg := &sync.WaitGroup{}
	closedChan := make(chan struct{})
	dumpLogger := l.NewDumpLogger("query")

	var d dumper.Dumper
	dFlag := viper.GetString("dumper")

	switch dFlag {
	case "hex":
		d = &dumper.HexDumper{
			Logger: dumpLogger,
		}
	case "pg":
		d = &dumper.PgDumper{
			Logger: dumpLogger,
		}
	case "mysql":
		d = &dumper.MysqlDumper{
			Logger: dumpLogger,
		}
	default:
		d = &dumper.HexDumper{
			Logger: dumpLogger,
		}
	}

	return &Server{
		listenAddr: lAddr,
		remoteAddr: rAddr,
		ctx:        innerCtx,
		shutdown:   shutdown,
		Wg:         wg,
		ClosedChan: closedChan,
		logger:     logger,
		Dumper:     d,
	}
}

// Start server.
func (s *Server) Start() error {
	useServerSterter := viper.GetBool("useServerSterter")

	if useServerSterter {
		listeners, err := listener.ListenAll()
		if listeners == nil || err != nil {
			return err
		}
		lt := listeners[0].(*net.TCPListener)
		s.listener = lt
	} else {
		lt, err := net.ListenTCP("tcp", s.listenAddr)
		if err != nil {
			return err
		}
		s.listener = lt
	}
	defer func() {
		s.listener.Close()
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
		s.listener.Close()
	}
}

// GracefulShutdown server.
func (s *Server) GracefulShutdown() {
	select {
	case <-s.ctx.Done():
	default:
		s.listener.Close()
	}
}

func (s *Server) handleConn(conn *net.TCPConn) {
	defer func() {
		conn.Close()
		s.Wg.Done()
	}()

	remoteConn, err := net.DialTCP("tcp", nil, s.remoteAddr)
	defer remoteConn.Close()
	if err != nil {
		log.Println(err)
		return
	}

	p := NewProxy(s, conn, remoteConn)
	p.Start()
}
