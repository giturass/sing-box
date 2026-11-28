package httpdebug

import (
	"encoding/json"
	"testing"
)

func TestForceHTTPEngineHostsPortOrderAndTLSBoundary(t *testing.T) {
	config := &HTTPRoutingConfig{Enabled: true, ForceHTTPEngineHosts: []string{"-excluded.test:0", "bare.test", "*.example.test:8080", "any.test:0", "excluded.test:8080"}}
	if err := config.validate(); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		host     string
		port     uint16
		protocol string
		want     bool
	}{
		{"bare.test", 8080, "http", false}, {"bare.test", 80, "http", true},
		{"sub.example.test", 8080, "http", true}, {"sub.example.test", 8081, "http", false},
		{"any.test", 1234, "http", true}, {"excluded.test", 8080, "http", false},
		{"excluded.test", 80, "http", true}, {"any.test", 443, "tls", false},
	} {
		if got := config.candidate(Metadata{Host: test.host, Port: test.port, Protocol: test.protocol}); got != test.want {
			t.Errorf("%s:%d/%s=%v, want %v", test.host, test.port, test.protocol, got, test.want)
		}
	}
	for _, pattern := range []string{"host.test:", "host.test:65536", "host.test:-1", "http://host.test", "", "bad host", "[invalid]:80"} {
		data, _ := json.Marshal(HTTPRoutingConfig{Enabled: true, ForceHTTPEngineHosts: []string{pattern}})
		var invalid HTTPRoutingConfig
		if err := json.Unmarshal(data, &invalid); err == nil {
			t.Errorf("invalid force host accepted: %q", pattern)
		}
	}
}

func TestForceHTTPEngineHostListTokensAndIPv6(t *testing.T) {
	for _, test := range []struct {
		hosts []string
		host  string
		port  uint16
		want  bool
	}{
		{[]string{"<ip-address>:8080"}, "192.0.2.1", 8080, true},
		{[]string{"<ip-address>:8080"}, "2001:db8::1", 8080, true},
		{[]string{"<ip-address>:8080"}, "host.test", 8080, false},
		{[]string{"<ip-address>"}, "192.0.2.1", 8080, false},
		{[]string{"<ipv4-address>:0"}, "192.0.2.1", 1234, true},
		{[]string{"<ipv4-address>:0"}, "2001:db8::1", 1234, false},
		{[]string{"<ipv6-address>:8080"}, "2001:db8::1", 8080, true},
		{[]string{"<ipv6-address>:8080"}, "192.0.2.1", 8080, false},
		{[]string{"<simple-hostname>:8080"}, "router", 8080, true},
		{[]string{"<simple-hostname>:8080"}, "router.test", 8080, false},
		{[]string{"<simple-hostname>:8080"}, "192.0.2.1", 8080, false},
		{[]string{"[2001:db8::1]:8080"}, "2001:db8::1", 8080, true},
		{[]string{"[2001:db8::1]:8080"}, "2001:db8::1", 8081, false},
		{[]string{"2001:db8::1"}, "2001:db8::1", 8080, false},
		{[]string{"-<ipv4-address>:0", "<ip-address>:0"}, "192.0.2.1", 8080, false},
		{[]string{"-<ipv4-address>:0", "<ip-address>:0"}, "2001:db8::1", 8080, true},
	} {
		config := &HTTPRoutingConfig{Enabled: true, ForceHTTPEngineHosts: test.hosts}
		if err := config.validate(); err != nil {
			t.Fatal(err)
		}
		if got := config.candidate(Metadata{Host: test.host, Port: test.port, Protocol: "http", sniffedSNI: true}); got != test.want {
			t.Errorf("%v %s:%d=%v, want %v", test.hosts, test.host, test.port, got, test.want)
		}
	}
}
