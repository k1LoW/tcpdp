package dumper

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/k1LoW/tcpdp/logger"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	comQuery       = 0x03
	comStmtPrepare = 0x16
	comStmtExecute = 0x17

	comStmtPrepareOK = 0x00
)

type mysqlType byte

const (
	mysqlTypeDecimal    mysqlType = 0x00
	mysqlTypeTiny                 = 0x01
	mysqlTypeShort                = 0x02
	mysqlTypeLong                 = 0x03
	mysqlTypeFloat                = 0x04
	mysqlTypeDouble               = 0x05
	mysqlTypeNull                 = 0x06
	mysqlTypeTimestamp            = 0x07
	mysqlTypeLonglong             = 0x08
	mysqlTypeInt24                = 0x09
	mysqlTypeDate                 = 0x0a
	mysqlTypeTime                 = 0x0b
	mysqlTypeDatetime             = 0x0c
	mysqlTypeYear                 = 0x0d
	mysqlTypeNewdate              = 0x0e
	mysqlTypeVarchar              = 0x0f
	mysqlTypeBit                  = 0x10
	mysqlTypeNewdecimal           = 0xf6
	mysqlTypeEnum                 = 0xf7
	mysqlTypeSet                  = 0xf8
	mysqlTypeTinyBlob             = 0xf9
	mysqlTypeMediumblob           = 0xfa
	mysqlTypeLongblob             = 0xfb
	mysqlTypeBlob                 = 0xfc
	mysqlTypeVarString            = 0xfd
	mysqlTypeString               = 0xfe
	mysqlTypeGeometry             = 0xff
)

const (
	clientLongPassword uint32 = 1 << iota
	clientFoundRows
	clientLongFlag
	clientConnectWithDB
	clientNoSchema
	clientCompress
	clientODBC
	clientLocalFiles
	clientIgnoreSpace
	clientProtocol41
	clientInteractive
	clientSSL
	clientIgnoreSIGPIPE
	clientTransactions
	clientReserved
	clientSecureConnection
	clientMultiStatements
	clientMultiResults
	clientPSMultiResults
	clientPluginAuth
	clientConnectAttrs
	clientPluginAuthLenEncClientData
	clientCanHandleExpiredPasswords
	clientSessionTrack
	clientDeprecateEOF
)

// MysqlDumper struct
type MysqlDumper struct {
	name   string
	logger *zap.Logger
}

type stmtNumParams map[int]int // statement_id:num_params

// NewMysqlDumper returns a MysqlDumper
func NewMysqlDumper() *MysqlDumper {
	dumper := &MysqlDumper{
		name:   "mysql",
		logger: logger.NewQueryLogger(),
	}
	return dumper
}

// Name return dumper name
func (m *MysqlDumper) Name() string {
	return m.name
}

// Dump query of MySQL
func (m *MysqlDumper) Dump(in []byte, direction Direction, connMetadata *ConnMetadata, additional []DumpValue) error {
	pValues := m.ReadInitialDumpValues(in, direction, connMetadata)
	if len(pValues) > 0 {
		for _, kv := range pValues {
			connMetadata.DumpValues = append(connMetadata.DumpValues, kv)
		}
		return nil
	}

	read := m.Read(in, direction, connMetadata)
	if len(read) == 0 {
		return nil
	}

	values := []DumpValue{}
	values = append(values, read...)
	values = append(values, connMetadata.DumpValues...)
	values = append(values, additional...)

	m.Log(values)
	return nil
}

// Read return byte to analyzed string
func (m *MysqlDumper) Read(in []byte, direction Direction, connMetadata *ConnMetadata) []DumpValue {
	if direction == RemoteToClient || direction == DstToSrc || direction == Unknown {
		// COM_STMT_PREPARE Response https://dev.mysql.com/doc/internals/en/com-stmt-prepare-response.html
		if len(in) >= 16 && in[4] == comStmtPrepareOK && in[13] == 0x00 {
			buff := bytes.NewBuffer(in[5:])
			stmtID := readBytes(buff, 4)
			stmtIDNum := int(bytesToUint64(stmtID))
			_ = readBytes(buff, 2)
			numParams := readBytes(buff, 2)
			numParamsNum := int(bytesToUint64(numParams))
			connMetadata.Internal.(stmtNumParams)[stmtIDNum] = numParamsNum
		}
		if direction == RemoteToClient || direction == DstToSrc {
			return []DumpValue{}
		}
	}
	if len(in) < 6 {
		return []DumpValue{}
	}
	seqNum := int64(in[3])
	commandID := in[4]

	var dumps = []DumpValue{}
	switch commandID {
	case comQuery:
		query := strings.Trim(string(in[5:]), "\x00")
		dumps = []DumpValue{
			DumpValue{
				Key:   "query",
				Value: query,
			},
		}
	case comStmtPrepare:
		stmtPrepare := strings.Trim(string(in[5:]), "\x00")
		dumps = []DumpValue{
			DumpValue{
				Key:   "stmt_prepare",
				Value: stmtPrepare,
			},
		}
	case comStmtExecute:
		// https://dev.mysql.com/doc/internals/en/com-stmt-execute.html
		buff := bytes.NewBuffer(in[5:])
		stmtID := readBytes(buff, 4) // 4:stmt-id
		stmtIDNum := int(bytesToUint64(stmtID))
		numParamsNum, ok := connMetadata.Internal.(stmtNumParams)[stmtIDNum]
		if ok && numParamsNum > 0 {
			_ = readBytes(buff, 5)                  // 1:flags 4:iteration-count
			_ = readBytes(buff, (numParamsNum+7)/8) // NULL-bitmap, length: (num-params+7)/8
			newParamsBoundFlag, _ := buff.ReadByte()
			if newParamsBoundFlag == 0x01 {
				// type of each parameter, length: num-params * 2
				mysqlTypes := []mysqlType{}
				for i := 0; i < numParamsNum; i++ {
					t := readMysqlType(buff)
					mysqlTypes = append(mysqlTypes, t)
					_, _ = buff.ReadByte()
				}
				// value of each parameter
				values := []interface{}{}
				for i := 0; i < numParamsNum; i++ {
					// https://dev.mysql.com/doc/internals/en/binary-protocol-value.html
					v := readBinaryProtocolValue(buff, mysqlTypes[i])
					values = append(values, v)
				}
				dumps = []DumpValue{
					DumpValue{
						Key:   "stmt_id",
						Value: stmtIDNum,
					},
					DumpValue{
						Key:   "stmt_execute_values",
						Value: values,
					},
				}
			} else {
				dumps = []DumpValue{
					DumpValue{
						Key:   "stmt_id",
						Value: stmtIDNum,
					},
					DumpValue{
						Key:   "stmt_execute_values",
						Value: []interface{}{},
					},
				}
			}
		} else {
			dumps = []DumpValue{
				DumpValue{
					Key:   "stmt_id",
					Value: stmtIDNum,
				},
				DumpValue{
					Key:   "stmt_execute_values",
					Value: []interface{}{},
				},
			}
		}
	default:
		return []DumpValue{}
	}

	return append(dumps, []DumpValue{
		DumpValue{
			Key:   "seq_num",
			Value: seqNum,
		},
		DumpValue{
			Key:   "command_id",
			Value: commandID,
		},
	}...)
}

// ReadInitialDumpValues return persistent value each session
func (m *MysqlDumper) ReadInitialDumpValues(in []byte, direction Direction, connMetadata *ConnMetadata) []DumpValue {
	values := []DumpValue{}
	if direction == RemoteToClient || direction == DstToSrc {
		return values
	}
	if len(in) < 37 {
		return values
	}

	clientCapabilities := binary.LittleEndian.Uint32(in[4:8])

	// parse Protocol::HandshakeResponse41 to get username, database
	if clientCapabilities&clientProtocol41 > 0 && bytes.Compare(in[13:36], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) == 0 {
		buff := bytes.NewBuffer(in[36:])
		readed, _ := buff.ReadString(0x00)
		username := strings.Trim(readed, "\x00")
		values = append(values, DumpValue{
			Key:   "username",
			Value: username,
		})
		if clientCapabilities&clientPluginAuthLenEncClientData > 0 {
			n := readLengthEncodedInteger(buff)
			_, _ = buff.Read(make([]byte, n))
		} else if clientCapabilities&clientSecureConnection > 0 {
			l, _ := buff.ReadByte()
			_, _ = buff.Read(make([]byte, l))
		} else {
			_, _ = buff.ReadString(0x00)
		}
		if clientCapabilities&clientConnectWithDB > 0 {
			readed, _ := buff.ReadString(0x00)
			database := strings.Trim(readed, "\x00")
			values = append(values, DumpValue{
				Key:   "database",
				Value: database,
			})
		}
	}

	return values
}

// Log values
func (m *MysqlDumper) Log(values []DumpValue) {
	fields := []zapcore.Field{}
	for _, kv := range values {
		fields = append(fields, zap.Any(kv.Key, kv.Value))
	}
	m.logger.Info("-", fields...)
}

// NewConnMetadata ...
func (m *MysqlDumper) NewConnMetadata() *ConnMetadata {
	return &ConnMetadata{
		DumpValues: []DumpValue{},
		Internal:   stmtNumParams{},
	}
}

func readMysqlType(buff *bytes.Buffer) mysqlType {
	b, _ := buff.ReadByte()
	return mysqlType(b)
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
func readBinaryProtocolValue(buff *bytes.Buffer, mysqlType mysqlType) interface{} {
	switch mysqlType {
	case mysqlTypeLonglong:
		v := readBytes(buff, 8)
		return binary.LittleEndian.Uint64(v)
	case mysqlTypeLong, mysqlTypeInt24:
		return bytesToUint64(readBytes(buff, 4))
	case mysqlTypeShort, mysqlTypeYear:
		return bytesToUint64(readBytes(buff, 2))
	case mysqlTypeTiny:
		return bytesToUint64(readBytes(buff, 1))
	case mysqlTypeDouble:
		bits := bytesToUint64(readBytes(buff, 8))
		float := math.Float64frombits(bits)
		return float
	case mysqlTypeFloat:
		bits := bytesToUint64(readBytes(buff, 4))
		float := math.Float32frombits(uint32(bits))
		return float
	case mysqlTypeDate, mysqlTypeDatetime, mysqlTypeTimestamp:
		return readDatetime(buff, mysqlType)
	case mysqlTypeTime:
		return readTime(buff)
	case mysqlTypeNull:
		return nil
	default:
		l := readLengthEncodedInteger(buff)
		v := readBytes(buff, int(l))
		return string(v)
	}
}

// ProtocolBinary::MYSQL_TYPE_DATE, ProtocolBinary::MYSQL_TYPE_DATETIME, ProtocolBinary::MYSQL_TYPE_TIMESTAMP
// https://dev.mysql.com/doc/internals/en/binary-protocol-value.html
func readDatetime(buff *bytes.Buffer, mysqlType mysqlType) string {
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

	if mysqlType == mysqlTypeDate {
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

func bytesToUint64(b []byte) uint64 {
	padding := make([]byte, 8-len(b))
	return binary.LittleEndian.Uint64(append(b, padding...))
}
