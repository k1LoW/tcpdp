package dumper

import (
	"github.com/k1LoW/tcprxy/logger"
	"go.uber.org/zap"
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
func (m *MysqlDumper) Dump(cid string, in []byte) error {
	commandID := in[4]
	if commandID != comQuery && commandID != comStmtPrepare && commandID != comStmtExecute {
		return nil
	}
	n := len(in)
	query := string(in[5:n])
	m.logger.Info(query, zap.String("command_id", string(in[4])), zap.String("cid", cid))
	return nil
}
