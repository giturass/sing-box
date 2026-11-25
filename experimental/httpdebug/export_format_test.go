package httpdebug

import (
	"bytes"
	"net"
	"testing"
)

func TestHARQueryKeepsOrderAndUndecodableParameters(t *testing.T) {
	query := harQuery("http://origin.test/path?b=2&a=1&b=%zz&flag&c=x+y")
	want := [][2]string{{"b", "2"}, {"a", "1"}, {"b", "%zz"}, {"flag", ""}, {"c", "x y"}}
	if len(query) != len(want) {
		t.Fatalf("unexpected query: %v", query)
	}
	for i, item := range want {
		if query[i]["name"] != item[0] || query[i]["value"] != item[1] {
			t.Fatalf("parameter %d: %v", i, query[i])
		}
	}
}

func TestHARCookies(t *testing.T) {
	request := harCookies(Message{Headers: []Header{{Name: "cookie", Value: "a=1; b=2"}}}, false)
	if len(request) != 2 || request[0]["name"] != "a" || request[1]["value"] != "2" {
		t.Fatalf("request cookies: %v", request)
	}
	response := harCookies(Message{Headers: []Header{{Name: "Set-Cookie", Value: "sid=x; Path=/; Secure; HttpOnly"}, {Name: "Set-Cookie", Value: "=bad"}}}, true)
	if len(response) != 1 || response[0]["name"] != "sid" || response[0]["path"] != "/" || response[0]["secure"] != true || response[0]["httpOnly"] != true {
		t.Fatalf("response cookies: %v", response)
	}
}

func TestTLSProbeStopsAtLineLimit(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go client.Write(bytes.Repeat([]byte{'A'}, tlsProbeLineLimit+1024))
	result := probeHTTPRequestLine(server)
	if result.http1 || len(result.data) < tlsProbeLineLimit || len(result.data) > tlsProbeLineLimit+4096 {
		t.Fatalf("probe read %d bytes, http1=%v", len(result.data), result.http1)
	}
}
