package server

import (
	"context"
	"net"
	"strings"

	"github.com/rs/xid"
	"go.uber.org/zap"
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
	}()

	guid := xid.New()

	go p.pipe(guid.String(), p.conn, p.remoteConn)
	go p.pipe(guid.String(), p.remoteConn, p.conn)

	select {
	case <-p.ctx.Done():
		return
	}
}

func (p *Proxy) pipe(cid string, srcConn, destConn *net.TCPConn) {
	defer p.Close()

	buff := make([]byte, 0xFFFF)
	for {
		n, err := srcConn.Read(buff)
		if err != nil {
			if err.Error() != "EOF" && !strings.Contains(err.Error(), "use of closed network connection") {
				p.server.logger.WithOptions(zap.AddCaller()).Error("strCon Read error", zap.Error(err))
			}
			break
		}
		b := buff[:n]

		err = p.server.Dumper.Dump(cid, b)
		if err != nil {
			p.server.logger.WithOptions(zap.AddCaller()).Error("dumber Dump error", zap.Error(err))
			break
		}

		n, err = destConn.Write(b)
		if err != nil {
			p.server.logger.WithOptions(zap.AddCaller()).Error("destCon Write error", zap.Error(err))
			break
		}

		select {
		case <-p.ctx.Done():
			break
		default:
		}
	}
}
