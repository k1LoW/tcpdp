package dumper

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

// DumpValues ...
type DumpValues struct {
	Values []DumpValue
}

// Dumper interface
type Dumper interface {
	Name() string
	Dump(in []byte, direction Direction, persistent *DumpValues, additional []DumpValue) error
	Read(in []byte) []DumpValue
	ReadPersistentValues(in []byte) []DumpValue
	Log(values []DumpValue)
}
