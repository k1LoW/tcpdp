package mysql

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/k1LoW/tcpdp/dumper"
	"github.com/k1LoW/tcpdp/logger"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Dumper struct
type Dumper struct {
	name   string
	logger *zap.Logger
}

type clientCapabilities map[clientCapability]bool

type stmtNumParams map[int]int // statement_id:num_params

type connMetadataInternal struct {
	clientCapabilities clientCapabilities
	stmtNumParams      stmtNumParams
	charSet            charSet
	payloadLength      uint32
	longPacketCache    []byte
}

// NewDumper returns a Dumper
func NewDumper() *Dumper {
	dumper := &Dumper{
		name:   "mysql",
		logger: logger.NewQueryLogger(),
	}
	return dumper
}

// Name return dumper name
func (m *Dumper) Name() string {
	return m.name
}

// Dump query of MySQL
func (m *Dumper) Dump(in []byte, direction dumper.Direction, connMetadata *dumper.ConnMetadata, additional []dumper.DumpValue) error {
	read, _ := m.Read(in, direction, connMetadata)
	if len(read) == 0 {
		return nil
	}

	values := []dumper.DumpValue{}
	values = append(values, read...)
	values = append(values, connMetadata.DumpValues...)
	values = append(values, additional...)

	m.Log(values)
	return nil
}

// Read return byte to analyzed string
func (m *Dumper) Read(in []byte, direction dumper.Direction, connMetadata *dumper.ConnMetadata) ([]dumper.DumpValue, error) {
	values, handshakeErr := m.readHandshakeResponse(in, direction, connMetadata)

	connMetadata.DumpValues = append(connMetadata.DumpValues, values...)
	cSet := connMetadata.Internal.(connMetadataInternal).charSet

	if len(connMetadata.Internal.(connMetadataInternal).longPacketCache) > 0 {
		internal := connMetadata.Internal.(connMetadataInternal)
		in = append(internal.longPacketCache, in...)
		internal.longPacketCache = nil
		connMetadata.Internal = internal
	}

	if handshakeErr != nil {
		return values, handshakeErr
	}

	// Client Compress
	compressed, ok := connMetadata.Internal.(connMetadataInternal).clientCapabilities[clientCompress]
	if ok && compressed {
		// https://dev.mysql.com/doc/internals/en/compressed-packet-header.html
		buff := bytes.NewBuffer(in)
		lenCompressed := int(bytesToUint64(readBytes(buff, 3))) // 3:length of compressed payload
		_ = readBytes(buff, 1)                                  // 1:compressed sequence id
		lenUncompressed := bytesToUint64(readBytes(buff, 3))    // 3:length of payload before compression
		if buff.Len() == lenCompressed {
			if lenUncompressed > 0 {
				// https://dev.mysql.com/doc/internals/en/compressed-payload.html
				r, err := zlib.NewReader(buff)
				if err != nil {
					return values, err
				}
				newBuff := new(bytes.Buffer)
				_, err = io.Copy(newBuff, r)
				if err != nil {
					return values, err
				}
				in = newBuff.Bytes()
			} else {
				// https://dev.mysql.com/doc/internals/en/uncompressed-payload.html
				in = buff.Bytes()
			}
		}
	}

	if direction == dumper.RemoteToClient || direction == dumper.DstToSrc || direction == dumper.Unknown {
		// COM_STMT_PREPARE Response https://dev.mysql.com/doc/internals/en/com-stmt-prepare-response.html
		if len(in) >= 16 && in[4] == comStmtPrepareOK && in[13] == 0x00 {
			buff := bytes.NewBuffer(in[5:])
			stmtID := readBytes(buff, 4)
			stmtIDNum := int(bytesToUint64(stmtID))
			_ = readBytes(buff, 2)
			numParams := readBytes(buff, 2)
			numParamsNum := int(bytesToUint64(numParams))
			connMetadata.Internal.(connMetadataInternal).stmtNumParams[stmtIDNum] = numParamsNum
		}
		return []dumper.DumpValue{}, nil
	}

	if len(in) < 6 {
		return []dumper.DumpValue{}, nil
	}

	var payloadLength uint32
	internal := connMetadata.Internal.(connMetadataInternal)
	if internal.payloadLength > 0 {
		payloadLength = internal.payloadLength
	} else {
		pl := make([]byte, 3)
		copy(pl, in[0:3])
		payloadLength = bytesToUint32(pl) // 3:payload_length
	}
	if uint32(len(in[4:])) < payloadLength {
		internal.payloadLength = payloadLength
		internal.longPacketCache = append(internal.longPacketCache, in...)
		connMetadata.Internal = internal
		return []dumper.DumpValue{}, nil
	}
	internal.payloadLength = uint32(0)
	connMetadata.Internal = internal

	seqNum := int64(in[3])
	commandID := in[4]

	var dumps = []dumper.DumpValue{}
	switch commandID {
	case comQuery:
		query := readString(in[5:], cSet)
		dumps = []dumper.DumpValue{
			dumper.DumpValue{
				Key:   "query",
				Value: query,
			},
		}
	case comStmtPrepare:
		stmtPrepare := readString(in[5:], cSet)
		dumps = []dumper.DumpValue{
			dumper.DumpValue{
				Key:   "stmt_prepare_query",
				Value: stmtPrepare,
			},
		}
	case comStmtExecute:
		// https://dev.mysql.com/doc/internals/en/com-stmt-execute.html
		buff := bytes.NewBuffer(in[5:])
		stmtID := readBytes(buff, 4) // 4:stmt-id
		stmtIDNum := int(bytesToUint64(stmtID))
		numParamsNum, ok := connMetadata.Internal.(connMetadataInternal).stmtNumParams[stmtIDNum]
		if ok && numParamsNum > 0 {
			_ = readBytes(buff, 5)                  // 1:flags 4:iteration-count
			_ = readBytes(buff, (numParamsNum+7)/8) // NULL-bitmap, length: (num-params+7)/8
			newParamsBoundFlag, _ := buff.ReadByte()
			if newParamsBoundFlag == 0x01 {
				// type of each parameter, length: num-params * 2
				dataTypes := []dataType{}
				for i := 0; i < numParamsNum; i++ {
					t := readMysqlType(buff)
					dataTypes = append(dataTypes, t)
					_, _ = buff.ReadByte()
				}
				// value of each parameter
				values := []interface{}{}
				for i := 0; i < numParamsNum; i++ {
					// https://dev.mysql.com/doc/internals/en/binary-protocol-value.html
					v := readBinaryProtocolValue(buff, dataTypes[i], cSet)
					values = append(values, v)
				}
				dumps = []dumper.DumpValue{
					dumper.DumpValue{
						Key:   "stmt_id",
						Value: stmtIDNum,
					},
					dumper.DumpValue{
						Key:   "stmt_execute_values",
						Value: values,
					},
				}
			} else {
				dumps = []dumper.DumpValue{
					dumper.DumpValue{
						Key:   "stmt_id",
						Value: stmtIDNum,
					},
					dumper.DumpValue{
						Key:   "stmt_execute_values",
						Value: []interface{}{},
					},
				}
			}
		} else if ok && numParamsNum == 0 {
			dumps = []dumper.DumpValue{
				dumper.DumpValue{
					Key:   "stmt_id",
					Value: stmtIDNum,
				},
				dumper.DumpValue{
					Key:   "stmt_execute_values",
					Value: []interface{}{},
				},
			}
		} else {
			values := readString(in[5:], cSet)
			dumps = []dumper.DumpValue{
				dumper.DumpValue{
					Key:   "stmt_id",
					Value: stmtIDNum,
				},
				dumper.DumpValue{
					Key:   "stmt_execute_values",
					Value: []string{values},
				},
			}
		}
	default:
		return []dumper.DumpValue{}, nil
	}

	return append(dumps, []dumper.DumpValue{
		dumper.DumpValue{
			Key:   "seq_num",
			Value: seqNum,
		},
		dumper.DumpValue{
			Key:   "command_id",
			Value: commandID,
		},
	}...), nil
}

// Log values
func (m *Dumper) Log(values []dumper.DumpValue) {
	fields := []zapcore.Field{}
	for _, kv := range values {
		fields = append(fields, zap.Any(kv.Key, kv.Value))
	}
	m.logger.Info("-", fields...)
}

// NewConnMetadata return metadata per TCP connection
func (m *Dumper) NewConnMetadata() *dumper.ConnMetadata {
	return &dumper.ConnMetadata{
		DumpValues: []dumper.DumpValue{},
		Internal: connMetadataInternal{
			stmtNumParams:      stmtNumParams{},
			clientCapabilities: clientCapabilities{},
			charSet:            charSetUnknown,
			payloadLength:      uint32(0),
		},
	}
}

func (m *Dumper) readHandshakeResponse(in []byte, direction dumper.Direction, connMetadata *dumper.ConnMetadata) ([]dumper.DumpValue, error) {
	values := []dumper.DumpValue{}
	if direction == dumper.RemoteToClient || direction == dumper.DstToSrc {
		return values, nil
	}

	if len(connMetadata.Internal.(connMetadataInternal).clientCapabilities) > 0 {
		return values, nil
	}

	if len(in) < 9 {
		return values, nil
	}

	clientCapabilities := binary.LittleEndian.Uint32(in[4:8])

	// parse Protocol::HandshakeResponse41
	if len(in) > 35 && clientCapabilities&uint32(clientProtocol41) > 0 && bytes.Compare(in[13:36], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) == 0 {
		internal := connMetadata.Internal.(connMetadataInternal)

		cSet := charSet(uint32(in[12]))
		values = append(values, dumper.DumpValue{
			Key:   "character_set",
			Value: cSet.String(),
		})
		internal.charSet = cSet
		connMetadata.Internal = internal
		connMetadata.Internal.(connMetadataInternal).clientCapabilities[clientProtocol41] = true

		if clientCapabilities&uint32(clientSSL) > 0 {
			// tcpdp mysql dumper not support SSL connection.
			err := errors.New("client is trying to connect using SSL. tcpdp mysql dumper not support SSL connection")
			fields := []zapcore.Field{
				zap.Error(err),
			}
			for _, kv := range connMetadata.DumpValues {
				fields = append(fields, zap.Any(kv.Key, kv.Value))
			}
			for _, kv := range values {
				fields = append(fields, zap.Any(kv.Key, kv.Value))
			}
			m.logger.Warn("-", fields...)
			return values, err
		}

		buff := bytes.NewBuffer(in[36:])
		readed, _ := buff.ReadBytes(0x00)
		username := readString(readed, cSet)
		values = append(values, dumper.DumpValue{
			Key:   "username",
			Value: username,
		})
		if clientCapabilities&uint32(clientPluginAuthLenEncClientData) > 0 {
			connMetadata.Internal.(connMetadataInternal).clientCapabilities[clientPluginAuthLenEncClientData] = true
			n := readLengthEncodedInteger(buff)
			_, _ = buff.Read(make([]byte, n))
		} else if clientCapabilities&uint32(clientSecureConnection) > 0 {
			connMetadata.Internal.(connMetadataInternal).clientCapabilities[clientSecureConnection] = true
			l, _ := buff.ReadByte()
			_, _ = buff.Read(make([]byte, l))
		} else {
			_, _ = buff.ReadString(0x00)
		}
		if clientCapabilities&uint32(clientConnectWithDB) > 0 {
			connMetadata.Internal.(connMetadataInternal).clientCapabilities[clientConnectWithDB] = true
			readed, _ := buff.ReadBytes(0x00)
			database := readString(readed, cSet)
			values = append(values, dumper.DumpValue{
				Key:   "database",
				Value: database,
			})
		}
		connMetadata.Internal.(connMetadataInternal).clientCapabilities[clientCompress] = (clientCapabilities&uint32(clientCompress) > 0)
		return values, nil
	}

	// parse Protocol::HandshakeResponse320
	clientCapabilities = bytesToUint32(in[4:6]) // 2:capability flags, CLIENT_PROTOCOL_41 never set
	if clientCapabilities&uint32(clientProtocol41) == 0 {
		if clientCapabilities&uint32(clientSSL) > 0 {
			// tcpdp mysql dumper not support SSL connection.
			err := errors.New("client is trying to connect using SSL. tcpdp mysql dumper not support SSL connection")
			return values, err
		}

		v := []dumper.DumpValue{}
		internal := connMetadata.Internal.(connMetadataInternal)
		connMetadata.Internal = internal
		connMetadata.Internal.(connMetadataInternal).clientCapabilities[clientProtocol41] = false
		buff := bytes.NewBuffer(in[9:])
		readed, _ := buff.ReadBytes(0x00)
		username := readString(readed, charSetUtf8)
		v = append(v, dumper.DumpValue{
			Key:   "username",
			Value: username,
		})
		if clientCapabilities&uint32(clientConnectWithDB) > 0 {
			_, _ = buff.ReadBytes(0x00)
			readed, _ := buff.ReadBytes(0x00)
			database := readString(readed, charSetUtf8)
			v = append(v, dumper.DumpValue{
				Key:   "database",
				Value: database,
			})
		} else {
			_, _ = buff.ReadBytes(0x00)
		}
		if buff.Len() == 0 {
			values = append(values, v...)
		}
	}

	return values, nil
}

func readMysqlType(buff *bytes.Buffer) dataType {
	b, _ := buff.ReadByte()
	return dataType(b)
}

// https://dev.mysql.com/doc/internals/en/integer.html#length-encoded-integer
func readLengthEncodedInteger(buff *bytes.Buffer) uint64 {
	l, _ := buff.ReadByte()
	n := bytesToUint64([]byte{l})
	if l == 0xfc {
		n = bytesToUint64(readBytes(buff, 2))
	}
	if l == 0xfd {
		n = bytesToUint64(readBytes(buff, 3))
	}
	if l == 0xfe {
		n = bytesToUint64(readBytes(buff, 8))
	}
	return n
}

// https://dev.mysql.com/doc/internals/en/binary-protocol-value.html
func readBinaryProtocolValue(buff *bytes.Buffer, dataType dataType, cSet charSet) interface{} {
	switch dataType {
	case typeLonglong:
		v := readBytes(buff, 8)
		return int64(binary.LittleEndian.Uint64(v))
	case typeLong, typeInt24:
		v := readBytes(buff, 4)
		return int32(binary.LittleEndian.Uint32(v))
	case typeShort, typeYear:
		v := readBytes(buff, 2)
		return int16(binary.LittleEndian.Uint16(v))
	case typeTiny:
		v := readBytes(buff, 1)
		return int8(v[0])
	case typeDouble:
		bits := bytesToUint64(readBytes(buff, 8))
		float := math.Float64frombits(bits)
		return float
	case typeFloat:
		bits := bytesToUint64(readBytes(buff, 4))
		float := math.Float32frombits(uint32(bits))
		return float
	case typeDate, typeDatetime, typeTimestamp:
		return readDatetime(buff, dataType)
	case typeTime:
		return readTime(buff)
	case typeNull:
		return nil
	default:
		l := readLengthEncodedInteger(buff)
		v := readBytes(buff, int(l))
		return readString(v, cSet)
	}
}

// ProtocolBinary::MYSQL_TYPE_DATE, ProtocolBinary::MYSQL_TYPE_DATETIME, ProtocolBinary::MYSQL_TYPE_TIMESTAMP
// https://dev.mysql.com/doc/internals/en/binary-protocol-value.html
func readDatetime(buff *bytes.Buffer, dataType dataType) string {
	l := bytesToUint64(readBytes(buff, 1))
	year := 0
	var month time.Month
	day := 0
	hour := 0
	min := 0
	sec := 0
	microSecond := 0
	switch l {
	case 0:
	case 4:
		year = int(bytesToUint64(readBytes(buff, 2)))
		month = time.Month(int(bytesToUint64(readBytes(buff, 1))))
		day = int(bytesToUint64(readBytes(buff, 1)))
	case 7:
		year = int(bytesToUint64(readBytes(buff, 2)))
		month = time.Month(int(bytesToUint64(readBytes(buff, 1))))
		day = int(bytesToUint64(readBytes(buff, 1)))
		hour = int(bytesToUint64(readBytes(buff, 1)))
		min = int(bytesToUint64(readBytes(buff, 1)))
		sec = int(bytesToUint64(readBytes(buff, 1)))
	case 11:
		year = int(bytesToUint64(readBytes(buff, 2)))
		month = time.Month(int(bytesToUint64(readBytes(buff, 1))))
		day = int(bytesToUint64(readBytes(buff, 1)))
		hour = int(bytesToUint64(readBytes(buff, 1)))
		min = int(bytesToUint64(readBytes(buff, 1)))
		sec = int(bytesToUint64(readBytes(buff, 1)))
		microSecond = int(bytesToUint64(readBytes(buff, 4)))
	}
	t := time.Date(year, month, day, hour, min, sec, microSecond*1000, time.UTC)

	if dataType == typeDate {
		return t.Format("2006-01-02")
	}
	ms := fmt.Sprintf("%06d", microSecond)
	return fmt.Sprintf("%s.%s %s", t.Format("2006-01-02 15:04:05"), ms[0:3], ms[3:6])
}

// ProtocolBinary::MYSQL_TYPE_TIME
// https://dev.mysql.com/doc/internals/en/binary-protocol-value.html
func readTime(buff *bytes.Buffer) string {
	l := bytesToUint64(readBytes(buff, 1))
	days := 0
	negative := 0
	hour := 0
	min := 0
	sec := 0
	microSecond := 0
	switch l {
	case 0:
	case 8:
		negative = int(bytesToUint64(readBytes(buff, 1)))
		days = int(bytesToUint64(readBytes(buff, 4)))
		hour = int(bytesToUint64(readBytes(buff, 1)))
		min = int(bytesToUint64(readBytes(buff, 1)))
		sec = int(bytesToUint64(readBytes(buff, 1)))
	case 12:
		negative = int(bytesToUint64(readBytes(buff, 1)))
		days = int(bytesToUint64(readBytes(buff, 4)))
		hour = int(bytesToUint64(readBytes(buff, 1)))
		min = int(bytesToUint64(readBytes(buff, 1)))
		sec = int(bytesToUint64(readBytes(buff, 1)))
		microSecond = int(bytesToUint64(readBytes(buff, 4)))
	}
	op := ""
	if negative == 1 {
		op = "-"
	}
	t := time.Date(0, time.January, 0, hour, min, sec, microSecond*1000, time.UTC)
	ms := fmt.Sprintf("%06d", microSecond)
	switch l {
	case 0:
		return ""
	case 12:
		return fmt.Sprintf("%s%dd %s.%s %s", op, days, t.Format("15:04:05"), ms[0:3], ms[3:6])
	default:
		return fmt.Sprintf("%s%dd %s", op, days, t.Format("15:04:05"))
	}

}

func bytesToUint32(b []byte) uint32 {
	c := make([]byte, len(b))
	copy(c, b)
	padding := make([]byte, 4-len(c))
	return binary.LittleEndian.Uint32(append(c, padding...))
}

func bytesToUint64(b []byte) uint64 {
	c := make([]byte, len(b))
	copy(c, b)
	padding := make([]byte, 8-len(c))
	return binary.LittleEndian.Uint64(append(c, padding...))
}

func readBytes(buff *bytes.Buffer, len int) []byte {
	b := make([]byte, len)
	_, _ = buff.Read(b)
	return b
}
