package server

import (
	"context"
	"net"
	"strings"

	"github.com/k1LoW/tcprxy/dumper"
	"github.com/rs/xid"
	"go.uber.org/zap"
)

// Direction of TCP commnication
type Direction int

const (
	// ClientToRemote is client->proxy->remote
	ClientToRemote Direction = iota
	// RemoteToClient is client<-proxy<-remote
	RemoteToClient
)

func (d Direction) String() string {
	switch d {
	case ClientToRemote:
		return "->"
	case RemoteToClient:
		return "<-"
	default:
		return "?"
	}
}

// Proxy struct
type Proxy struct {
	server     *Server
	ctx        context.Context
	Close      context.CancelFunc
	connID     string
	conn       *net.TCPConn
	remoteConn *net.TCPConn
	dumpValues []dumper.DumpValue
}

// NewProxy returns a new Proxy
func NewProxy(s *Server, conn, remoteConn *net.TCPConn) *Proxy {
	innerCtx, close := context.WithCancel(s.ctx)

	connID := xid.New().String()

	dumpValues := []dumper.DumpValue{
		dumper.DumpValue{
			Key:   "connection_id",
			Value: connID,
		},
		dumper.DumpValue{
			Key:   "client_addr",
			Value: conn.RemoteAddr().String(),
		},
		dumper.DumpValue{
			Key:   "proxy_listen_addr",
			Value: conn.LocalAddr().String(),
		},
		dumper.DumpValue{
			Key:   "proxy_client_addr",
			Value: remoteConn.LocalAddr().String(),
		},
		dumper.DumpValue{
			Key:   "remote_addr",
			Value: remoteConn.RemoteAddr().String(),
		},
	}

	return &Proxy{
		server:     s,
		ctx:        innerCtx,
		Close:      close,
		connID:     connID,
		conn:       conn,
		remoteConn: remoteConn,
		dumpValues: dumpValues,
	}
}

// Start proxy
func (p *Proxy) Start() {
	defer func() {
		p.conn.Close()
		p.remoteConn.Close()
	}()

	go p.pipe(p.conn, p.remoteConn)
	go p.pipe(p.remoteConn, p.conn)

	select {
	case <-p.ctx.Done():
		return
	}
}

func (p *Proxy) dump(b []byte, direction Direction) error {
	kvs := append(p.dumpValues, dumper.DumpValue{
		Key:   "direction",
		Value: direction.String(),
	})

	return p.server.dumper.Dump(b, kvs)
}

func (p *Proxy) pipe(srcConn, destConn *net.TCPConn) {
	defer p.Close()

	var direction Direction
	if p.server.remoteAddr.String() == destConn.RemoteAddr().String() {
		direction = ClientToRemote
	}

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

		err = p.dump(b, direction)
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
