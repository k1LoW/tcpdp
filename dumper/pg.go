package dumper

import (
	"bytes"
	"fmt"
	"strings"

	"go.uber.org/zap"
)

// PgDumper struct
type PgDumper struct {
	Logger *zap.Logger
}

// Dump query of PostgreSQL
func (p *PgDumper) Dump(in []byte) error {
	if in[0] != 'Q' {
		return nil
	}
	buff := bytes.NewBuffer(in)
	_, _ = buff.ReadByte()
	_, _ = buff.Read(make([]byte, 4))
	str, _ := buff.ReadString(0x00)
	query := strings.Trim(str, "\x00")
	p.Logger.Info(fmt.Sprintf("%s", query))
	return nil
}
