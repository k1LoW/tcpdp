package reader

import "testing"

var parseTargetTests = []struct {
	target            string
	expectedHost      string
	expectedPort      uint16
	expectedBPFFilter string
}{
	{
		"localhost:80",
		"127.0.0.1",
		uint16(80),
		"tcp and host 127.0.0.1 and port 80",
	},
	{
		"0.0.0.0:80",
		"0.0.0.0",
		uint16(80),
		"tcp port 80",
	},
	{
		"80",
		"",
		uint16(80),
		"tcp port 80",
	},
	{
		"127.0.0.1",
		"127.0.0.1",
		uint16(0),
		"tcp and host 127.0.0.1",
	},
	{
		"",
		"",
		uint16(0),
		"tcp",
	},
	{
		"0.0.0.0:0",
		"0.0.0.0",
		uint16(0),
		"tcp",
	},
	{
		"0.0.0.0",
		"0.0.0.0",
		uint16(0),
		"tcp",
	},
}

func TestParseTarget(t *testing.T) {
	for _, tt := range parseTargetTests {
		target := tt.target
		actualHost, actualPort, err := ParseTarget(target)

		if err != nil {
			t.Errorf("%v", err)
		}

		if actualHost != tt.expectedHost {
			t.Errorf("actual %v\nwant %v", actualHost, tt.expectedHost)
		}

		if actualPort != tt.expectedPort {
			t.Errorf("actual %v\nwant %v", actualPort, tt.expectedPort)
		}
	}
}

func TestNewBPFFilterString(t *testing.T) {
	for _, tt := range parseTargetTests {
		target := tt.target
		host, port, err := ParseTarget(target)

		if err != nil {
			t.Errorf("%v", err)
		}

		expected := tt.expectedBPFFilter
		actual := NewBPFFilterString(host, port)

		if actual != expected {
			t.Errorf("actual %v\nwant %v", actual, expected)
		}
	}
}
