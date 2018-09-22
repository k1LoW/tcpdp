package dumper

import "bytes"

// Direction of TCP commnication
type Direction int

const (
	// ClientToRemote is client->proxy->remote
	ClientToRemote Direction = iota
	// RemoteToClient is client<-proxy<-remote
	RemoteToClient
	// SrcToDst is src->dst
	SrcToDst
	// DstToSrc is dst->src
	DstToSrc
	// Unknown direction
	Unknown Direction = 9
)

func (d Direction) String() string {
	switch d {
	case ClientToRemote, SrcToDst:
		return "->"
	case RemoteToClient, DstToSrc:
		return "<-"
	default:
		return "?"
	}
}

// DumpValue ...
type DumpValue struct {
	Key   string
	Value interface{}
}

// ConnMetadata is metadada per TCP connection
type ConnMetadata struct {
	DumpValues []DumpValue
	Internal   interface{} // internal metadata for dumper
}

// Dumper interface
type Dumper interface {
	Name() string
	Dump(in []byte, direction Direction, connMetadata *ConnMetadata, additional []DumpValue) error
	Read(in []byte, direction Direction, connMetadata *ConnMetadata) []DumpValue
	ReadInitialDumpValues(in []byte, direction Direction, connMetadata *ConnMetadata) []DumpValue
	Log(values []DumpValue)
	NewConnMetadata() *ConnMetadata
}

func readBytes(buff *bytes.Buffer, len int) []byte {
	b := make([]byte, len)
	_, _ = buff.Read(b)
	return b
}
