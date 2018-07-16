package server

import (
	"context"
	"net"
)

// Server struct
type Server struct{}

// Start TCP proxy server.
func (s *Server) Start(listenAddr, remoteAddr *net.TCPAddr) error {
	lt, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		return err
	}
	defer lt.Close()

	for {
		conn, err := lt.AcceptTCP()
		if err != nil {
			return err
		}
		go s.handleConn(conn, remoteAddr)
	}
}

func (s *Server) handleConn(conn *net.TCPConn, remoteAddr *net.TCPAddr) {
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	remoteConn, err := net.DialTCP("tcp", nil, remoteAddr)
	defer remoteConn.Close()
	if err != nil {
		// TODO: error handling
		return
	}

	p := &Proxy{}
	p.Start(ctx, conn, remoteConn)
}
