package dumper

import (
	"bytes"
	"encoding/binary"
	"strings"

	"github.com/k1LoW/tcprxy/logger"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	comQuery       = 0x03
	comStmtPrepare = 0x16
	comStmtExecute = 0x17
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
func (m *MysqlDumper) Dump(in []byte, direction Direction, persistent *DumpValues, additional []DumpValue) error {
	if direction == RemoteToClient {
		return nil
	}
	if len(in) < 6 {
		return nil
	}

	pValues := m.ReadPersistentValues(in)
	if len(pValues) > 0 {
		for _, kv := range pValues {
			persistent.Values = append(persistent.Values, kv)
		}
		return nil
	}

	read := m.Read(in)
	if len(read) == 0 {
		return nil
	}

	values := []DumpValue{}
	values = append(values, read...)
	values = append(values, persistent.Values...)
	values = append(values, additional...)

	m.Log(values)
	return nil
}

// Read return byte to analyzed string
func (m *MysqlDumper) Read(in []byte) []DumpValue {
	if len(in) < 6 {
		return []DumpValue{}
	}
	seqNum := int64(in[3])
	commandID := in[4]
	if commandID != comQuery && commandID != comStmtPrepare && commandID != comStmtExecute {
		return []DumpValue{}
	}
	query := strings.Trim(string(in[5:]), "\x00")
	return []DumpValue{
		DumpValue{
			Key:   "query",
			Value: query,
		},
		DumpValue{
			Key:   "seq_num",
			Value: seqNum,
		},
		DumpValue{
			Key:   "command_id",
			Value: commandID,
		},
	}
}

// ReadPersistentValues return persistent value each session
func (m *MysqlDumper) ReadPersistentValues(in []byte) []DumpValue {
	values := []DumpValue{}
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
			l, _ := buff.ReadByte()
			if l == 0xfc {
				_, _ = buff.Read(make([]byte, 2))
			}
			if l == 0xfd {
				_, _ = buff.Read(make([]byte, 3))
			}
			if l == 0xfe {
				_, _ = buff.Read(make([]byte, 8))
			}
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
