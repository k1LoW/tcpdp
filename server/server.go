package server

import (
	"context"
	"net"
	"sync"
)

// Server struct
type Server struct {
	ListenAddr *net.TCPAddr
	RemoteAddr *net.TCPAddr
	Ctx        context.Context
	Wg         *sync.WaitGroup
}

// Start TCP proxy server.
func (s *Server) Start() error {
	lt, err := net.ListenTCP("tcp", s.ListenAddr)
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

	innerCtx, cancel := context.WithCancel(s.Ctx)
	defer cancel()

	remoteConn, err := net.DialTCP("tcp", nil, s.RemoteAddr)
	defer remoteConn.Close()
	if err != nil {
		// TODO: error handling
		return
	}

	p := &Proxy{
		Ctx:        innerCtx,
		CloseFunc:  cancel,
		Conn:       conn,
		RemoteConn: remoteConn,
	}
	p.Start()
}
