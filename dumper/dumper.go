package dumper

// DumpValue ...
type DumpValue struct {
	Key   string
	Value interface{}
}

// Dumper interface
type Dumper interface {
	Dump(in []byte, kvs []DumpValue) error
}
