package dumper

import (
	"strings"

	"github.com/k1LoW/tcprxy/logger"
	"go.uber.org/zap"
)

const (
	pgMessageQuery = 'Q'
	pgMessageParse = 'P'
	pgMessageBind  = 'B'
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
	messageType := in[0]
	if messageType != pgMessageQuery && messageType != pgMessageParse && messageType != pgMessageBind {
		return nil
	}
	n := len(in)
	query := strings.Trim(string(in[5:n]), "\x00")
	p.logger.Info(query, zap.String("message_type", string(messageType)), zap.String("cid", cid))
	return nil
}
