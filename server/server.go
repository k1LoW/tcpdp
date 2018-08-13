package server

import (
	"context"
	"net"
	"sync"
)

// Server struct
type Server struct{}

// Start TCP proxy server.
func (s *Server) Start(ctx context.Context, wg *sync.WaitGroup, listenAddr, remoteAddr *net.TCPAddr) error {
	lt, err := net.ListenTCP("tcp", listenAddr)
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
		wg.Add(1)
		go s.handleConn(ctx, wg, conn, remoteAddr)
	}
}

func (s *Server) handleConn(ctx context.Context, wg *sync.WaitGroup, conn *net.TCPConn, remoteAddr *net.TCPAddr) {
	defer func() {
		conn.Close()
		wg.Done()
	}()

	innerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	remoteConn, err := net.DialTCP("tcp", nil, remoteAddr)
	defer remoteConn.Close()
	if err != nil {
		// TODO: error handling
		return
	}

	p := &Proxy{}
	p.Start(innerCtx, conn, remoteConn)
}
