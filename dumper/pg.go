package dumper

import (
	"bytes"
	"strings"

	"github.com/k1LoW/tcpdp/logger"
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
	name   string
	logger *zap.Logger
}

// NewPgDumper returns a PgDumper
func NewPgDumper() *PgDumper {
	dumper := &PgDumper{
		name:   "pg",
		logger: logger.NewQueryLogger(),
	}
	return dumper
}

// Name return dumper name
func (p *PgDumper) Name() string {
	return p.name
}

// Dump query of PostgreSQL
func (p *PgDumper) Dump(in []byte, direction Direction, connMetadata *ConnMetadata, additional []DumpValue) error {
	// parse StartupMessage to get username, database
	pValues := p.ReadInitialDumpValues(in, direction, connMetadata)
	if len(pValues) > 0 {
		for _, kv := range pValues {
			connMetadata.DumpValues = append(connMetadata.DumpValues, kv)
		}
		return nil
	}

	read := p.Read(in, direction, connMetadata)
	if len(read) == 0 {
		return nil
	}

	values := []DumpValue{}
	values = append(values, read...)
	values = append(values, connMetadata.DumpValues...)
	values = append(values, additional...)

	p.Log(values)
	return nil
}

// Read return byte to analyzed string
func (p *PgDumper) Read(in []byte, direction Direction, connMetadata *ConnMetadata) []DumpValue {
	if direction == RemoteToClient || direction == DstToSrc {
		return []DumpValue{}
	}

	messageType := in[0]
	if messageType != pgMessageQuery && messageType != pgMessageParse && messageType != pgMessageBind {
		return []DumpValue{}
	}
	query := strings.Trim(string(in[5:]), "\x00")
	return []DumpValue{
		DumpValue{
			Key:   "query",
			Value: query,
		},
		DumpValue{
			Key:   "message_type",
			Value: string(messageType),
		},
	}
}

// ReadInitialDumpValues return persistent value each session
func (p *PgDumper) ReadInitialDumpValues(in []byte, direction Direction, connMetadata *ConnMetadata) []DumpValue {
	values := []DumpValue{}
	if direction == RemoteToClient || direction == DstToSrc {
		return values
	}
	// parse StartupMessage to get username, database
	if len(in) < 10 {
		return values
	}
	splited := bytes.Split(in[8:], []byte{0x00})
	if len(splited) > 0 {
		for i, keyOrValue := range splited {
			if i%2 != 0 {
				continue
			}
			if string(keyOrValue) == "user" {
				values = append(values, DumpValue{
					Key:   "username",
					Value: string(splited[i+1]),
				})
			}
			if string(keyOrValue) == "database" {
				values = append(values, DumpValue{
					Key:   "database",
					Value: string(splited[i+1]),
				})
			}
		}
	}
	return values
}

// Log values
func (p *PgDumper) Log(values []DumpValue) {
	fields := []zapcore.Field{}
	for _, kv := range values {
		fields = append(fields, zap.Any(kv.Key, kv.Value))
	}
	p.logger.Info("-", fields...)
}

// NewConnMetadata ...
func (p *PgDumper) NewConnMetadata() *ConnMetadata {
	return &ConnMetadata{
		DumpValues: []DumpValue{},
	}
}
