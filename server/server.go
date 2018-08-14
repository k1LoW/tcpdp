package server

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/lestrrat-go/server-starter/listener"
	"github.com/spf13/viper"
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
}

// NewServer returns a new Server
func NewServer(ctx context.Context, lAddr, rAddr *net.TCPAddr) *Server {
	innerCtx, shutdown := context.WithCancel(ctx)
	wg := &sync.WaitGroup{}
	closedChan := make(chan struct{})

	return &Server{
		listenAddr: lAddr,
		remoteAddr: rAddr,
		ctx:        innerCtx,
		shutdown:   shutdown,
		Wg:         wg,
		ClosedChan: closedChan,
	}
}

// Start server.
func (s *Server) Start() error {
	useServerSterter := viper.GetBool("useServerSterter")

	var lt *net.TCPListener
	if useServerSterter {
		listeners, err := listener.ListenAll()
		if listeners == nil || err != nil {
			return err
		}
		lt = listeners[0].(*net.TCPListener)
		s.listener = lt
	} else {
		lt, err := net.ListenTCP("tcp", s.listenAddr)
		if err != nil {
			return err
		}
		s.listener = lt
	}
	defer func() {
		lt.Close()
		close(s.ClosedChan)
	}()

	for {
		conn, err := lt.AcceptTCP()
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

	p := NewProxy(s.ctx, conn, remoteConn)
	p.Start()
}
