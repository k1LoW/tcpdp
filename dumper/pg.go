package dumper

import (
	"strings"

	"github.com/k1LoW/tcprxy/logger"
	"go.uber.org/zap"
)

// PgDumper struct
type PgDumper struct {
	logger *zap.Logger
}

// NewPgDumper returns a PgDumper
func NewPgDumper() *PgDumper {
	dumper := &PgDumper{
		logger: logger.NewQueryLogger(),
	}
	return dumper
}

// Dump query of PostgreSQL
func (p *PgDumper) Dump(cid string, in []byte) error {
	if in[0] != 'Q' {
		return nil
	}
	n := len(in)
	query := strings.Trim(string(in[5:n]), "\x00")
	p.logger.Info(query, zap.String("cid", cid))
	return nil
}
