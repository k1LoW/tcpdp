package dumper

import (
	"strings"

	"go.uber.org/zap"
)

// PgDumper struct
type PgDumper struct {
	Logger *zap.Logger
}

// Dump query of PostgreSQL
func (p *PgDumper) Dump(cid string, in []byte) error {
	if in[0] != 'Q' {
		return nil
	}
	n := len(in)
	query := strings.Trim(string(in[5:n]), "\x00")
	p.Logger.Info(query, zap.String("cid", cid))
	return nil
}
