package mysql

import "strings"

func decodeString(src []byte, srcCharSet charSet) string {
	return strings.TrimRight(string(src), "\x00")
}
