package server

import (
	"context"
	"net"
)

// Proxy struct
type Proxy struct {
	ctx        context.Context
	Close      context.CancelFunc
	conn       *net.TCPConn
	remoteConn *net.TCPConn
	server     *Server
}

// NewProxy returns a new Proxy
func NewProxy(s *Server, conn, remoteConn *net.TCPConn) *Proxy {
	innerCtx, close := context.WithCancel(s.ctx)

	return &Proxy{
		ctx:        innerCtx,
		Close:      close,
		conn:       conn,
		remoteConn: remoteConn,
		server:     s,
	}
}

// Start proxy
func (p *Proxy) Start() {
	defer func() {
		p.conn.Close()
		p.remoteConn.Close()
		p.Close()
	}()

	go p.pipe(p.conn, p.remoteConn)
	go p.pipe(p.remoteConn, p.conn)

	select {
	case <-p.ctx.Done():
		return
	}
}

func (p *Proxy) pipe(srcConn, destConn *net.TCPConn) {
	defer p.Close()

	buff := make([]byte, 0xFFFF)
	for {
		n, err := srcConn.Read(buff)
		if err != nil {
			break
		}
		b := buff[:n]

		err = p.server.Dumper.Dump(b)
		if err != nil {
			break
		}

		n, err = destConn.Write(b)
		if err != nil {
			break
		}

		select {
		case <-p.ctx.Done():
			break
		default:
		}
	}
}
