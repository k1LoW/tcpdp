package reader

import (
	"reflect"
	"testing"
)

var parseTargetTests = []struct {
	target        string
	wantTarget    Target
	wantBPFFilter string
}{
	{
		"localhost:80",
		Target{
			TargetHosts: []TargetHost{
				TargetHost{
					Host: "127.0.0.1",
					Port: uint16(80),
				},
			},
		},
		"tcp and ((host 127.0.0.1 and port 80))",
	},
	{
		"0.0.0.0:80",
		Target{
			TargetHosts: []TargetHost{
				TargetHost{
					Host: "0.0.0.0",
					Port: uint16(80),
				},
			},
		},
		"tcp and ((port 80))",
	},
	{
		"80",
		Target{
			TargetHosts: []TargetHost{
				TargetHost{
					Host: "",
					Port: uint16(80),
				},
			},
		},
		"tcp and ((port 80))",
	},
	{
		"127.0.0.1",
		Target{
			TargetHosts: []TargetHost{
				TargetHost{
					Host: "127.0.0.1",
					Port: uint16(0),
				},
			},
		},
		"tcp and ((host 127.0.0.1))",
	},
	{
		"",
		Target{
			TargetHosts: []TargetHost{
				TargetHost{
					Host: "",
					Port: uint16(0),
				},
			},
		},
		"tcp",
	},
	{
		"0.0.0.0:0",
		Target{
			TargetHosts: []TargetHost{
				TargetHost{
					Host: "0.0.0.0",
					Port: uint16(0),
				},
			},
		},
		"tcp",
	},
	{
		"0.0.0.0",
		Target{
			TargetHosts: []TargetHost{
				TargetHost{
					Host: "0.0.0.0",
					Port: uint16(0),
				},
			},
		},
		"tcp",
	},
	{
		"127.0.0.1||203.0.113.1",
		Target{
			TargetHosts: []TargetHost{
				TargetHost{
					Host: "127.0.0.1",
					Port: uint16(0),
				},
				TargetHost{
					Host: "203.0.113.1",
					Port: uint16(0),
				},
			},
		},
		"tcp and ((host 127.0.0.1) or (host 203.0.113.1))",
	},
	{
		"127.0.0.1 || 203.0.113.1",
		Target{
			TargetHosts: []TargetHost{
				TargetHost{
					Host: "127.0.0.1",
					Port: uint16(0),
				},
				TargetHost{
					Host: "203.0.113.1",
					Port: uint16(0),
				},
			},
		},
		"tcp and ((host 127.0.0.1) or (host 203.0.113.1))",
	},
	{
		"127.0.0.1:80 || 203.0.113.1:80",
		Target{
			TargetHosts: []TargetHost{
				TargetHost{
					Host: "127.0.0.1",
					Port: uint16(80),
				},
				TargetHost{
					Host: "203.0.113.1",
					Port: uint16(80),
				},
			},
		},
		"tcp and ((host 127.0.0.1 and port 80) or (host 203.0.113.1 and port 80))",
	},
	{
		"127.0.0.1:80 || 127.0.0.1:443",
		Target{
			TargetHosts: []TargetHost{
				TargetHost{
					Host: "127.0.0.1",
					Port: uint16(80),
				},
				TargetHost{
					Host: "127.0.0.1",
					Port: uint16(443),
				},
			},
		},
		"tcp and ((host 127.0.0.1 and port 80) or (host 127.0.0.1 and port 443))",
	},
	{
		"80 || 127.0.0.1:443",
		Target{
			TargetHosts: []TargetHost{
				TargetHost{
					Host: "",
					Port: uint16(80),
				},
				TargetHost{
					Host: "127.0.0.1",
					Port: uint16(443),
				},
			},
		},
		"tcp and ((port 80) or (host 127.0.0.1 and port 443))",
	},
	{
		"0.0.0.0 || 127.0.0.1:443",
		Target{
			TargetHosts: []TargetHost{
				TargetHost{
					Host: "0.0.0.0",
					Port: uint16(0),
				},
				TargetHost{
					Host: "127.0.0.1",
					Port: uint16(443),
				},
			},
		},
		"tcp",
	},
}

func TestParseTarget(t *testing.T) {
	for _, tt := range parseTargetTests {
		target := tt.target
		gotTarget, err := ParseTarget(target)

		if err != nil {
			t.Errorf("%v", err)
		}

		if !reflect.DeepEqual(gotTarget, tt.wantTarget) {
			t.Errorf("got %v\nwant %v", gotTarget, tt.wantTarget)
		}
	}
}

func TestNewBPFFilterString(t *testing.T) {
	for _, tt := range parseTargetTests {
		target := tt.target
		gotTarget, err := ParseTarget(target)

		if err != nil {
			t.Errorf("%v", err)
		}

		want := tt.wantBPFFilter
		got := NewBPFFilterString(gotTarget)

		if got != want {
			t.Errorf("got %v\nwant %v", got, want)
		}
	}
}
