package server

import (
	"context"
	"net"
	"sync"
)

// Server struct
type Server struct {
	listenAddr *net.TCPAddr
	remoteAddr *net.TCPAddr
	ctx        context.Context
	Shutdown   context.CancelFunc
	Wg         *sync.WaitGroup
}

// NewServer ...
func NewServer(ctx context.Context, lAddr, rAddr *net.TCPAddr) *Server {
	innerCtx, shutdown := context.WithCancel(ctx)
	wg := &sync.WaitGroup{}

	return &Server{
		listenAddr: lAddr,
		remoteAddr: rAddr,
		ctx:        innerCtx,
		Shutdown:   shutdown,
		Wg:         wg,
	}
}

// Start TCP proxy server.
func (s *Server) Start() error {
	lt, err := net.ListenTCP("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	defer lt.Close()

	for {
		conn, err := lt.AcceptTCP()
		if err != nil {
			if ne, ok := err.(net.Error); ok {
				if ne.Temporary() {
					continue
				}
			}
			return err
		}
		s.Wg.Add(1)
		go s.handleConn(conn)
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
		// TODO: error handling
		return
	}

	p := NewProxy(s.ctx, conn, remoteConn)
	defer p.Close()

	p.Start()
}
