package dumper

// Dumper interface
type Dumper interface {
	Dump(in []byte) error
}
