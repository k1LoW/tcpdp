package dumper

import (
	"bytes"
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
func (p *PgDumper) Dump(in []byte, direction Direction, persistent *DumpValues, additional []DumpValue) error {
	if direction == RemoteToClient {
		return nil
	}

	// StartupMessage
	if len(in) > 9 {
		splited := bytes.Split(in[8:], []byte{0x00})
		if len(splited) > 0 && string(splited[0]) == "user" {
			username := string(splited[1])
			persistent.Values = append(persistent.Values, DumpValue{
				Key:   "username",
				Value: username,
			})
			for i, keyOrValue := range splited {
				if string(keyOrValue) == "database" {
					persistent.Values = append(persistent.Values, DumpValue{
						Key:   "database",
						Value: string(splited[i+1]),
					})
				}
			}
			fields := []zapcore.Field{}
			for _, kv := range persistent.Values {
				fields = append(fields, zap.Any(kv.Key, kv.Value))
			}
			for _, kv := range additional {
				fields = append(fields, zap.Any(kv.Key, kv.Value))
			}
			return nil
		}
	}

	// Query
	messageType := in[0]
	if messageType != pgMessageQuery && messageType != pgMessageParse && messageType != pgMessageBind {
		return nil
	}

	query := strings.Trim(string(in[5:]), "\x00")
	fields := []zapcore.Field{
		zap.String("message_type", string(messageType)),
	}
	for _, kv := range persistent.Values {
		fields = append(fields, zap.Any(kv.Key, kv.Value))
	}
	for _, kv := range additional {
		fields = append(fields, zap.Any(kv.Key, kv.Value))
	}

	p.logger.Info(query, fields...)
	return nil
}
