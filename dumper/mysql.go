package dumper

import (
	"go.uber.org/zap"
)

// MysqlDumper struct
type MysqlDumper struct {
	Logger *zap.Logger
}

// Dump query of MySQL
func (m *MysqlDumper) Dump(cid string, in []byte) error {
	if in[4] != 0x03 {
		return nil
	}
	n := len(in)
	query := string(in[5:n])
	m.Logger.Info(query, zap.String("cid", cid))
	return nil
}
