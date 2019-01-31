package reader

import (
	"reflect"
	"testing"

	"github.com/k1LoW/tcpdp/dumper"
)

var parseProxyProtocolHeaderTests = []struct {
	in             []byte
	wantSeek       int
	wantDumpValues []dumper.DumpValue
	wantError      error
}{
	{
		// https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/enable-proxy-protocol.html
		[]byte("PROXY TCP4 198.51.100.22 203.0.113.7 35646 80\r\n"),
		57,
		[]dumper.DumpValue{
			dumper.DumpValue{
				Key:   "proxy_protocol_src_addr",
				Value: "198.51.100.22",
			},
			dumper.DumpValue{
				Key:   "proxy_protocol_dst_addr",
				Value: "203.0.113.7",
			},
			dumper.DumpValue{
				Key:   "proxy_protocol_src_port",
				Value: int64(35646),
			},
			dumper.DumpValue{
				Key:   "proxy_protocol_dst_port",
				Value: int64(80),
			},
		},
		nil,
	},
}

// TestParseProxyProtocolHeaderTest ...
func TestParseProxyProtocolHeaderTest(t *testing.T) {
	for _, tt := range parseProxyProtocolHeaderTests {
		seek, dumpValues, err := ParseProxyProtocolHeader(tt.in)

		if seek != tt.wantSeek {
			t.Errorf("got %v\nwant %v", seek, tt.wantSeek)
		}

		if !reflect.DeepEqual(dumpValues, tt.wantDumpValues) {
			t.Errorf("got %v\nwant %v", dumpValues, tt.wantDumpValues)
		}

		if err != tt.wantError {
			t.Errorf("got %v\nwant %v", err, tt.wantError)
		}
	}
}
