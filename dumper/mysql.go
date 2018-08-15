package dumper

import (
	"github.com/k1LoW/tcprxy/logger"
	"go.uber.org/zap"
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
	if in[4] != 0x03 {
		return nil
	}
	n := len(in)
	query := string(in[5:n])
	m.logger.Info(query, zap.String("cid", cid))
	return nil
}
