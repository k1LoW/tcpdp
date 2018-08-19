package dumper

// DumpValue ...
type DumpValue struct {
	Key   string
	Value string
}

// Dumper interface
type Dumper interface {
	Dump(in []byte, kvs []DumpValue) error
}
