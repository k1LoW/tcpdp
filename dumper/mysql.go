package dumper

import (
	"github.com/k1LoW/tcprxy/logger"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	comQuery       = 0x03
	comStmtPrepare = 0x16
	comStmtExecute = 0x17
)

// MysqlDumper struct
type MysqlDumper struct {
	logger *zap.Logger
}

// NewMysqlDumper returns a MysqlDumper
func NewMysqlDumper() *MysqlDumper {
	dumper := &MysqlDumper{
		logger: logger.NewQueryLogger(),
	}
	return dumper
}

// Dump query of MySQL
func (m *MysqlDumper) Dump(in []byte, direction Direction, kvs []DumpValue) error {
	if direction == RemoteToClient {
		return nil
	}
	if len(in) < 6 {
		return nil
	}
	commandID := in[4]
	if commandID != comQuery && commandID != comStmtPrepare && commandID != comStmtExecute {
		return nil
	}
	n := len(in)
	query := string(in[5:n])
	fields := []zapcore.Field{
		zap.String("command_id", string(in[4])),
	}
	for _, kv := range kvs {
		fields = append(fields, zap.Any(kv.Key, kv.Value))
	}

	m.logger.Info(query, fields...)
	return nil
}
