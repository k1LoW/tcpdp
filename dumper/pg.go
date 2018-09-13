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
func (p *PgDumper) Dump(in []byte, direction Direction, persistent *DumpValues, additional []DumpValue) error {
	if direction == RemoteToClient {
		return nil
	}

	// parse StartupMessage to get username, database
	pValues := p.ReadPersistentValues(in)
	if len(pValues) > 0 {
		for _, kv := range pValues {
			persistent.Values = append(persistent.Values, kv)
		}
		return nil
	}

	read := p.Read(in)
	if len(read) == 0 {
		return nil
	}

	values := []DumpValue{}
	values = append(values, read...)
	values = append(values, persistent.Values...)
	values = append(values, additional...)

	p.Log(values)
	return nil
}

// Read return byte to analyzed string
func (p *PgDumper) Read(in []byte) []DumpValue {
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

// ReadPersistentValues return persistent value each session
func (p *PgDumper) ReadPersistentValues(in []byte) []DumpValue {
	values := []DumpValue{}
	// parse StartupMessage to get username, database
	if len(in) < 10 {
		return values
	}
	splited := bytes.Split(in[8:], []byte{0x00})
	if len(splited) > 0 && string(splited[0]) == "user" {
		username := string(splited[1])
		values = append(values, DumpValue{
			Key:   "username",
			Value: username,
		})
		for i, keyOrValue := range splited {
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
