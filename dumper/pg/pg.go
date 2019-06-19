package pg

import (
	"bytes"
	"encoding/binary"
	"strings"

	"github.com/k1LoW/tcpdp/dumper"
	"github.com/k1LoW/tcpdp/logger"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	messageQuery   = 'Q'
	messageParse   = 'P'
	messageBind    = 'B'
	messageExecute = 'E'
)

type dataType int16

const (
	typeString dataType = iota
	typeBinary
)

// Dumper struct
type Dumper struct {
	name   string
	logger *zap.Logger
}

type connMetadataInternal struct {
	messageLength   uint32
	longPacketCache []byte
}

// NewDumper returns a Dumper
func NewDumper() *Dumper {
	dumper := &Dumper{
		name:   "pg",
		logger: logger.NewQueryLogger(),
	}
	return dumper
}

// Name return dumper name
func (p *Dumper) Name() string {
	return p.name
}

// Dump query of PostgreSQL
func (p *Dumper) Dump(in []byte, direction dumper.Direction, connMetadata *dumper.ConnMetadata, additional []dumper.DumpValue) error {
	read, _ := p.Read(in, direction, connMetadata)
	if len(read) == 0 {
		return nil
	}

	values := []dumper.DumpValue{}
	values = append(values, read...)
	values = append(values, connMetadata.DumpValues...)
	values = append(values, additional...)

	p.Log(values)
	return nil
}

// Read return byte to analyzed string
func (p *Dumper) Read(in []byte, direction dumper.Direction, connMetadata *dumper.ConnMetadata) ([]dumper.DumpValue, error) {
	values, handshakeErr := p.readHandshake(in, direction, connMetadata)
	connMetadata.DumpValues = append(connMetadata.DumpValues, values...)

	if handshakeErr != nil {
		return values, handshakeErr
	}

	if direction == dumper.RemoteToClient || direction == dumper.DstToSrc || direction == dumper.Unknown {
		return []dumper.DumpValue{}, nil
	}

	if len(connMetadata.Internal.(connMetadataInternal).longPacketCache) > 0 {
		internal := connMetadata.Internal.(connMetadataInternal)
		in = append(internal.longPacketCache, in...)
		internal.longPacketCache = nil
		connMetadata.Internal = internal
	}

	if len(in) == 0 {
		return []dumper.DumpValue{}, nil
	}

	messageType := in[0]

	switch messageType {
	case messageQuery, messageParse, messageBind, messageExecute:
		var messageLength uint32
		internal := connMetadata.Internal.(connMetadataInternal)
		if internal.messageLength > 0 {
			messageLength = internal.messageLength
		} else {
			ml := make([]byte, 4)
			copy(ml, in[1:5])
			messageLength = binary.BigEndian.Uint32(ml)
		}
		if uint32(len(in[1:])) < messageLength {
			internal.messageLength = messageLength
			internal.longPacketCache = append(internal.longPacketCache, in...)
			connMetadata.Internal = internal
			return []dumper.DumpValue{}, nil
		}
		internal.messageLength = uint32(0)
		connMetadata.Internal = internal
	}

	var dumps = []dumper.DumpValue{}
	// https://www.postgresql.org/docs/10/static/protocol-message-formats.html
	switch messageType {
	case messageQuery:
		query := strings.TrimRight(string(in[5:]), "\x00")

		dumps = []dumper.DumpValue{
			dumper.DumpValue{
				Key:   "query",
				Value: query,
			},
		}
	case messageParse:
		buff := bytes.NewBuffer(in[5:])
		b, _ := buff.ReadString(0x00)
		stmtName := strings.TrimRight(b, "\x00")
		b, _ = buff.ReadString(0x00)
		query := strings.TrimRight(b, "\x00")
		numParams := int(binary.BigEndian.Uint16(readBytes(buff, 2)))
		for i := 0; i < numParams; i++ {
			// TODO
			// Int32: Specifies the object ID of the parameter data type. Placing a zero here is equivalent to leaving the type unspecified.
		}

		dumps = []dumper.DumpValue{
			dumper.DumpValue{
				Key:   "stmt_name",
				Value: stmtName,
			},
			dumper.DumpValue{
				Key:   "parse_query",
				Value: query,
			},
		}
	case messageBind:
		buff := bytes.NewBuffer(in[5:])
		b, _ := buff.ReadString(0x00)
		portalName := strings.TrimRight(b, "\x00")
		b, _ = buff.ReadString(0x00)
		stmtName := strings.TrimRight(b, "\x00")
		c := int(binary.BigEndian.Uint16(readBytes(buff, 2)))
		dataTypes := []dataType{}
		for i := 0; i < c; i++ {
			t := dataType(binary.BigEndian.Uint16(readBytes(buff, 2)))
			dataTypes = append(dataTypes, t)
		}
		numParams := int(binary.BigEndian.Uint16(readBytes(buff, 2)))
		if c == 0 {
			for i := 0; i < numParams; i++ {
				dataTypes = append(dataTypes, typeString)
			}
		}
		values := []interface{}{}
		for i := 0; i < numParams; i++ {
			n := int32(binary.BigEndian.Uint32(readBytes(buff, 4)))
			if n == -1 {
				continue
			}
			v := readBytes(buff, int(n))
			if dataTypes[i] == typeString {
				values = append(values, string(v))
			} else {
				values = append(values, v)
			}
		}

		dumps = []dumper.DumpValue{
			dumper.DumpValue{
				Key:   "portal_name",
				Value: portalName,
			},
			dumper.DumpValue{
				Key:   "stmt_name",
				Value: stmtName,
			},
			dumper.DumpValue{
				Key:   "bind_values",
				Value: values,
			},
		}
	case messageExecute:
		buff := bytes.NewBuffer(in[5:])
		b, _ := buff.ReadString(0x00)
		portalName := strings.Trim(b, "\x00")

		dumps = []dumper.DumpValue{
			dumper.DumpValue{
				Key:   "portal_name",
				Value: portalName,
			},
			dumper.DumpValue{
				Key:   "execute_query",
				Value: "",
			},
		}
	default:
		return []dumper.DumpValue{}, nil
	}
	return append(dumps, dumper.DumpValue{
		Key:   "message_type",
		Value: string(messageType),
	}), nil
}

// Log values
func (p *Dumper) Log(values []dumper.DumpValue) {
	fields := []zapcore.Field{}
	for _, kv := range values {
		fields = append(fields, zap.Any(kv.Key, kv.Value))
	}
	p.logger.Info("-", fields...)
}

// NewConnMetadata return metadata per TCP connection
func (p *Dumper) NewConnMetadata() *dumper.ConnMetadata {
	return &dumper.ConnMetadata{
		DumpValues: []dumper.DumpValue{},
		Internal: connMetadataInternal{
			messageLength: uint32(0),
		},
	}
}

func (p *Dumper) readHandshake(in []byte, direction dumper.Direction, connMetadata *dumper.ConnMetadata) ([]dumper.DumpValue, error) {
	values := []dumper.DumpValue{}
	if direction == dumper.RemoteToClient || direction == dumper.DstToSrc {
		return values, nil
	}
	if len(in) < 8 {
		return values, nil
	}
	b := make([]byte, 2)
	copy(b, in[4:6])
	pNo := binary.BigEndian.Uint16(b)
	if pNo == 1234 {
		// SSLRequest
		b := make([]byte, 2)
		copy(b, in[6:8])
		uNo := binary.BigEndian.Uint16(b)
		if uNo == 5679 {
			// tcpdp pg dumper not support SSL connection.
			err := errors.New("client is trying to connect using SSL. tcpdp pg dumper not support SSL connection")
			return values, err
		}
	}
	// parse StartupMessage to get username, database
	if pNo != 3 {
		return values, nil
	}
	splited := bytes.Split(in[8:], []byte{0x00})
	if len(splited) > 0 {
		for i, keyOrValue := range splited {
			if i%2 != 0 {
				continue
			}
			if string(keyOrValue) == "user" {
				values = append(values, dumper.DumpValue{
					Key:   "username",
					Value: string(splited[i+1]),
				})
			}
			if string(keyOrValue) == "database" {
				values = append(values, dumper.DumpValue{
					Key:   "database",
					Value: string(splited[i+1]),
				})
			}
		}
	}
	return values, nil
}

func readBytes(buff *bytes.Buffer, len int) []byte {
	b := make([]byte, len)
	_, _ = buff.Read(b)
	return b
}
