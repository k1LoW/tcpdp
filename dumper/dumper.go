package dumper

// Dumper interface
type Dumper interface {
	Dump(cid string, in []byte) error
}
