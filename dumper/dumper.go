package dumper

// Direction of TCP commnication
type Direction int

const (
	// ClientToRemote is client->proxy->remote
	ClientToRemote Direction = iota
	// RemoteToClient is client<-proxy<-remote
	RemoteToClient
)

func (d Direction) String() string {
	switch d {
	case ClientToRemote:
		return "->"
	case RemoteToClient:
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
	Dump(in []byte, direction Direction, persistent *DumpValues, additional []DumpValue) error
}
