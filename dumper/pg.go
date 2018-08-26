package dumper

import (
	"strings"

	"github.com/k1LoW/tcprxy/logger"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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
func (p *PgDumper) Dump(in []byte, kvs []DumpValue) error {
	messageType := in[0]
	if messageType != pgMessageQuery && messageType != pgMessageParse && messageType != pgMessageBind {
		return nil
	}
	n := len(in)
	query := strings.Trim(string(in[5:n]), "\x00")
	fields := []zapcore.Field{
		zap.String("message_type", string(messageType)),
	}
	for _, kv := range kvs {
		fields = append(fields, zap.Any(kv.Key, kv.Value))
	}

	p.logger.Info(query, fields...)
	return nil
}
