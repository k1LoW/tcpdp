package server

import (
	"context"
	"log"
	"net"

	"github.com/k1LoW/tcprxy/dumper"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// Proxy struct
type Proxy struct {
	ctx        context.Context
	Close      context.CancelFunc
	conn       *net.TCPConn
	remoteConn *net.TCPConn
	logger     *zap.Logger
}

// NewProxy returns a new Proxy
func NewProxy(ctx context.Context, conn, remoteConn *net.TCPConn, logger *zap.Logger) *Proxy {
	innerCtx, close := context.WithCancel(ctx)

	return &Proxy{
		ctx:        innerCtx,
		Close:      close,
		conn:       conn,
		remoteConn: remoteConn,
		logger:     logger,
	}
}

// Start proxy
func (p *Proxy) Start() {
	defer func() {
		p.conn.Close()
		p.remoteConn.Close()
		p.Close()
	}()

	var d dumper.Dumper

	dFlag := viper.GetString("dumper")

	switch dFlag {
	case "hex":
		d = &dumper.HexDumper{}
	case "pg":
		d = &dumper.PgDumper{}
	case "mysql":
		d = &dumper.MysqlDumper{}
	default:
		d = &dumper.HexDumper{}
	}

	go p.pipe(d, p.conn, p.remoteConn)
	go p.pipe(d, p.remoteConn, p.conn)

	select {
	case <-p.ctx.Done():
		return
	}
}

func (p *Proxy) pipe(d dumper.Dumper, srcConn, destConn *net.TCPConn) {
	defer p.Close()

	buff := make([]byte, 0xFFFF)
	for {
		n, err := srcConn.Read(buff)
		if err != nil {
			break
		}
		b := buff[:n]

		out, _ := d.Dump(b)
		if out != "" {
			log.Print(out)
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
