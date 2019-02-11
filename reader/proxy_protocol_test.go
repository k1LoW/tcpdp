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
		47,
		[]dumper.DumpValue{
			dumper.DumpValue{
				Key:   "proxy_protocol_src_addr",
				Value: "198.51.100.22:35646",
			},
			dumper.DumpValue{
				Key:   "proxy_protocol_dst_addr",
				Value: "203.0.113.7:80",
			},
		},
		nil,
	},
	{
		[]byte{
			0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
			0x21,
			0x11,
			0x00, 0x0c,
			0x7d, 0x19, 0x0a, 0x01,
			0x0a, 0x04, 0x05, 0x08,
			0x1f, 0x90,
			0x10, 0x68,
		},
		28,
		[]dumper.DumpValue{
			dumper.DumpValue{
				Key:   "proxy_protocol_src_addr",
				Value: "125.25.10.1:8080",
			},
			dumper.DumpValue{
				Key:   "proxy_protocol_dst_addr",
				Value: "10.4.5.8:4200",
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
			t.Errorf("\ngot  %#v\nwant %#v", dumpValues, tt.wantDumpValues)
		}

		if err != tt.wantError {
			t.Errorf("got %v\nwant %v", err, tt.wantError)
		}
	}
}
