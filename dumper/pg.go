package dumper

import (
	"bytes"
	"fmt"
	"strings"
)

// PgDumper struct
type PgDumper struct{}

// Dump query of PostgreSQL
func (p *PgDumper) Dump(in []byte) string {
	if in[0] != 'Q' {
		return ""
	}
	buff := bytes.NewBuffer(in)
	_, _ = buff.ReadByte()
	_, _ = buff.Read(make([]byte, 4))
	str, _ := buff.ReadString(0x00)
	query := strings.Trim(str, "\x00")
	return fmt.Sprintf("%s\n", query)
}
