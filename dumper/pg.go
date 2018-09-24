package dumper

import (
	"bytes"
	"encoding/binary"
	"strings"

	"github.com/k1LoW/tcpdp/logger"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	pgMessageQuery   = 'Q'
	pgMessageParse   = 'P'
	pgMessageBind    = 'B'
	pgMessageExecute = 'E'
)

type pgType int16

const (
	pgTypeString pgType = iota
	pgTypeBinary
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
	values := p.readUsernameAndDatabase(in, direction)
	connMetadata.DumpValues = append(connMetadata.DumpValues, values...)

	if direction == RemoteToClient || direction == DstToSrc {
		return []DumpValue{}
	}
	if len(in) == 0 {
		return []DumpValue{}
	}

	messageType := in[0]
	var dumps = []DumpValue{}
	// https://www.postgresql.org/docs/10/static/protocol-message-formats.html
	switch messageType {
	case pgMessageQuery:
		query := strings.Trim(string(in[5:]), "\x00")

		dumps = []DumpValue{
			DumpValue{
				Key:   "query",
				Value: query,
			},
		}
	case pgMessageParse:
		buff := bytes.NewBuffer(in[5:])
		b, _ := buff.ReadString(0x00)
		stmtName := strings.Trim(b, "\x00")
		b, _ = buff.ReadString(0x00)
		query := strings.Trim(b, "\x00")
		numParams := int(binary.BigEndian.Uint16(readBytes(buff, 2)))
		for i := 0; i < numParams; i++ {
			// TODO
			// Int32: Specifies the object ID of the parameter data type. Placing a zero here is equivalent to leaving the type unspecified.
		}

		dumps = []DumpValue{
			DumpValue{
				Key:   "stmt_name",
				Value: stmtName,
			},
			DumpValue{
				Key:   "parse_query",
				Value: query,
			},
		}
	case pgMessageBind:
		buff := bytes.NewBuffer(in[5:])
		b, _ := buff.ReadString(0x00)
		portalName := strings.Trim(b, "\x00")
		b, _ = buff.ReadString(0x00)
		stmtName := strings.Trim(b, "\x00")
		c := int(binary.BigEndian.Uint16(readBytes(buff, 2)))
		pgTypes := []pgType{}
		for i := 0; i < c; i++ {
			t := pgType(binary.BigEndian.Uint16(readBytes(buff, 2)))
			pgTypes = append(pgTypes, t)
		}
		numParams := int(binary.BigEndian.Uint16(readBytes(buff, 2)))
		if c == 0 {
			for i := 0; i < numParams; i++ {
				pgTypes = append(pgTypes, pgTypeString)
			}
		}
		values := []interface{}{}
		for i := 0; i < numParams; i++ {
			n := int32(binary.BigEndian.Uint32(readBytes(buff, 4)))
			if n == -1 {
				continue
			}
			v := readBytes(buff, int(n))
			if pgTypes[i] == pgTypeString {
				values = append(values, string(v))
			} else {
				values = append(values, v)
			}
		}

		dumps = []DumpValue{
			DumpValue{
				Key:   "portal_name",
				Value: portalName,
			},
			DumpValue{
				Key:   "stmt_name",
				Value: stmtName,
			},
			DumpValue{
				Key:   "bind_values",
				Value: values,
			},
		}
	case pgMessageExecute:
		buff := bytes.NewBuffer(in[5:])
		b, _ := buff.ReadString(0x00)
		portalName := strings.Trim(b, "\x00")

		dumps = []DumpValue{
			DumpValue{
				Key:   "portal_name",
				Value: portalName,
			},
			DumpValue{
				Key:   "execute_query",
				Value: "",
			},
		}
	default:
		return []DumpValue{}
	}
	return append(dumps, DumpValue{
		Key:   "message_type",
		Value: string(messageType),
	})
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

func (p *PgDumper) readUsernameAndDatabase(in []byte, direction Direction) []DumpValue {
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
