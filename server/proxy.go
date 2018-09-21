package server

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/k1LoW/tcpdp/dumper"
	"github.com/rs/xid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Proxy struct
type Proxy struct {
	server     *Server
	ctx        context.Context
	Close      context.CancelFunc
	connID     string
	conn       *net.TCPConn
	remoteConn *net.TCPConn
	connMetadata *dumper.ConnMetadata
	seqNum     uint64
}

// NewProxy returns a new Proxy
func NewProxy(s *Server, conn, remoteConn *net.TCPConn) *Proxy {
	innerCtx, close := context.WithCancel(s.ctx)

	connID := xid.New().String()

	connMetadata := &dumper.ConnMetadata{
		DumpValues: []dumper.DumpValue{
			dumper.DumpValue{
				Key:   "conn_id",
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
		},
	}

	return &Proxy{
		server:     s,
		ctx:        innerCtx,
		Close:      close,
		connID:     connID,
		conn:       conn,
		remoteConn: remoteConn,
		connMetadata: connMetadata,
		seqNum:     0,
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

func (p *Proxy) dump(b []byte, direction dumper.Direction) error {
	kvs := []dumper.DumpValue{
		dumper.DumpValue{
			Key:   "conn_seq_num",
			Value: p.seqNum,
		},
		dumper.DumpValue{
			Key:   "direction",
			Value: direction.String(),
		},
		dumper.DumpValue{
			Key:   "ts",
			Value: time.Now(),
		},
	}

	return p.server.dumper.Dump(b, direction, p.connMetadata, kvs)
}

func (p *Proxy) pipe(srcConn, destConn *net.TCPConn) {
	defer p.Close()

	var direction dumper.Direction
	if p.server.remoteAddr.String() == destConn.RemoteAddr().String() {
		direction = dumper.ClientToRemote
	} else {
		direction = dumper.RemoteToClient
	}

	buff := make([]byte, 0xFFFF)
	for {
		n, err := srcConn.Read(buff)
		if err != nil {
			if err.Error() != "EOF" && !strings.Contains(err.Error(), "use of closed network connection") {
				fields := p.fieldsWithErrorAndDirection(err, direction)
				p.server.logger.WithOptions(zap.AddCaller()).Error("strCon Read error", fields...)
			}
			break
		}
		b := buff[:n]

		// TODO: block invalid query/data
		err = p.dump(b, direction)
		if err != nil {
			fields := p.fieldsWithErrorAndDirection(err, direction)
			p.server.logger.WithOptions(zap.AddCaller()).Error("dumber Dump error", fields...)
			break
		}

		n, err = destConn.Write(b)
		if err != nil {
			fields := p.fieldsWithErrorAndDirection(err, direction)
			p.server.logger.WithOptions(zap.AddCaller()).Error("destCon Write error", fields...)
			break
		}

		select {
		case <-p.ctx.Done():
			break
		default:
			p.seqNum++
		}
	}
}

func (p *Proxy) fieldsWithErrorAndDirection(err error, direction dumper.Direction) []zapcore.Field {
	fields := []zapcore.Field{
		zap.Error(err),
		zap.Uint64("conn_seq_num", p.seqNum),
		zap.String("direction", direction.String()),
	}

	for _, kv := range p.connMetadata.DumpValues {
		fields = append(fields, zap.Any(kv.Key, kv.Value))
	}

	return fields
}
