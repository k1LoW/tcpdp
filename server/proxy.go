package server

import (
	"context"
	"log"
	"net"

	"github.com/k1LoW/tcprxy/dumper"
	"github.com/spf13/viper"
)

// Proxy struct
type Proxy struct {
	Ctx        context.Context
	CloseFunc  context.CancelFunc
	Conn       *net.TCPConn
	RemoteConn *net.TCPConn
}

// Start proxy
func (p *Proxy) Start() {
	defer func() {
		p.Conn.Close()
		p.RemoteConn.Close()
		p.CloseFunc()
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

	go p.pipe(d, p.Conn, p.RemoteConn)
	go p.pipe(d, p.RemoteConn, p.Conn)

	select {
	case <-p.Ctx.Done():
		// TODO: logging
		return
	}
}

func (p *Proxy) pipe(d dumper.Dumper, srcConn, destConn *net.TCPConn) {
	defer p.CloseFunc()

	buff := make([]byte, 0xFFFF)
	for {
		n, err := srcConn.Read(buff)
		if err != nil {
			break
		}
		b := buff[:n]

		err, out := d.Dump(b)
		if err != nil {
			break
		}
		if out != "" {
			log.Print(out)
		}

		n, err = destConn.Write(b)
		if err != nil {
			break
		}

		select {
		case <-p.Ctx.Done():
			break
		default:
		}
	}
}
