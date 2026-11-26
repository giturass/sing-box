package httpdebug

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSurgeRuleLinesParseAndKeepTheirText(t *testing.T) {
	const content = `{"enabled":true,
		"url_rewrite":["^http://old\\.test/(.*) http://new.test/$1","^http://moved\\.test https://new.test 302","^http://ad\\.test/ _ reject"],
		"header_rewrite":["^http://example\\.test header-add DNT 1","http-request ^http://example\\.test header-replace User-Agent Mozilla/5.0 (B-box)",
			"http-response ^http://example\\.test header-replace-regex Date 2022 2023","http-request ^http://example\\.test header-del Cookie"],
		"body_rewrite":["http-response ^http://example\\.test/ old new \"vip\":false \"vip\":true",
			"http-response-jq ^http://example\\.test/ '.debug = true | .name = \"B box\"'","http-request-jq ^http://example\\.test/ .ok=true"],
		"map_local":["^http://mock\\.test/json data-type=text data=\"{\"a\": \"b c\"}\" status-code=500 header=\"Content-Type:application/json|X-Mock: yes\"",
			"^http://mock\\.test/gif data-type=tiny-gif","^http://mock\\.test/file data=\"data/mock.json\" update-interval=3600",
			"^http://mock\\.test/base64 data=\"dGVzdA==\" data-type=base64 header=WC1Nb2NrOiB5ZXMKWC1Ud286IDI="]}`
	var config RewriteConfig
	if err := json.Unmarshal([]byte(content), &config); err != nil {
		t.Fatal(err)
	}
	if rule := config.URLRewrite[0]; rule.Pattern != `^http://old\.test/(.*)` || rule.Replacement != "http://new.test/$1" || rule.Action != "header" {
		t.Fatalf("URL rewrite: %+v", rule)
	}
	if config.URLRewrite[1].Action != "302" || config.URLRewrite[2].Action != "reject" {
		t.Fatalf("URL rewrite types: %+v", config.URLRewrite)
	}
	headers := config.HeaderRewrite
	if headers[0].Phase != "request" || headers[0].Operation != "add" || headers[0].Header != "DNT" || headers[0].Value != "1" ||
		headers[1].Operation != "replace" || headers[1].Value != "Mozilla/5.0 (B-box)" ||
		headers[2].Phase != "response" || headers[2].Operation != "replace_regex" || headers[2].Regex != "2022" || headers[2].Replacement != "2023" ||
		headers[3].Operation != "delete" || headers[3].Header != "Cookie" {
		t.Fatalf("header rewrite: %+v", headers)
	}
	bodies := config.BodyRewrite
	if bodies[0].Phase != "response" || bodies[0].Regex != "old" || bodies[0].Replacement != "new" ||
		len(bodies[0].more) != 1 || bodies[0].more[0] != (bodyReplace{`"vip":false`, `"vip":true`}) {
		t.Fatalf("body rewrite pairs: %+v", bodies[0])
	}
	if bodies[1].JQ == nil || *bodies[1].JQ != `.debug = true | .name = "B box"` || bodies[2].Phase != "request" || *bodies[2].JQ != ".ok=true" {
		t.Fatalf("jq lines: %+v %+v", bodies[1], bodies[2])
	}
	local := config.MapLocal
	if local[0].DataType != "text" || local[0].Data != `{"a": "b c"}` || local[0].Status != 500 || len(local[0].Headers) != 2 ||
		local[0].Headers[1] != (Header{"X-Mock", "yes"}) || local[1].DataType != "tiny-gif" ||
		local[2].DataType != "file" || local[2].Data != "data/mock.json" || local[2].UpdateInterval != 3600 ||
		local[3].DataType != "base64" || len(local[3].Headers) != 2 || local[3].Headers[1] != (Header{"X-Two", "2"}) {
		t.Fatalf("map local: %+v", local)
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var written, formatted map[string]any
	if err = json.Unmarshal([]byte(content), &written); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(encoded, &formatted); err != nil {
		t.Fatal(err)
	}
	for _, section := range []string{"url_rewrite", "header_rewrite", "body_rewrite", "map_local"} {
		before, _ := json.Marshal(written[section])
		after, _ := json.Marshal(formatted[section])
		if string(before) != string(after) {
			t.Fatalf("%s lines changed when formatted:\n%s\n%s", section, before, after)
		}
	}
}

func TestSurgeRuleLinesRejectMalformedText(t *testing.T) {
	for _, content := range []string{
		`{"body_rewrite":["^http://example\\.test old new"]}`,
		`{"body_rewrite":["http-response ^http://example\\.test old"]}`,
		`{"body_rewrite":["http-response-jq ^http://example\\.test"]}`,
		`{"body_rewrite":["http-response-jq ^http://example\\.test ''"]}`,
		`{"body_rewrite":["http-response [ old new"]}`,
		`{"body_rewrite":[""]}`,
		`{"body_rewrite":["http-response . a b\nhttp-response . c d"]}`,
		`{"body_rewrite":[1]}`,
		`{"url_rewrite":["^http://example\\.test"]}`,
		`{"url_rewrite":["^http://example\\.test http://new.test 302 extra"]}`,
		`{"url_rewrite":["^http://example\\.test http://new.test 301"]}`,
		`{"header_rewrite":["^http://example\\.test header-add DNT"]}`,
		`{"header_rewrite":["^http://example\\.test header-del DNT 1"]}`,
		`{"header_rewrite":["^http://example\\.test header-set DNT 1"]}`,
		`{"header_rewrite":["^http://example\\.test header-replace Content-Length 1"]}`,
		`{"map_local":["^http://mock\\.test data-type=text data=\"open"]}`,
		`{"map_local":["^http://mock\\.test data-type=text status-code=abc"]}`,
		`{"map_local":["^http://mock\\.test data-type=text status-code=100"]}`,
		`{"map_local":["^http://mock\\.test data-type=text mode=1"]}`,
		`{"map_local":["^http://mock\\.test"]}`,
		`{"map_local":[{"pattern":".","match":null,"data":"local"}]}`,
		`{"body_rewrite":[{"pattern":".","phase":"response","regex":"a","unknown":1}]}`,
	} {
		var config RewriteConfig
		if err := json.Unmarshal([]byte(content), &config); err == nil {
			t.Fatalf("accepted %s", content)
		}
	}
}

func TestSurgeBodyRewriteLinesApplyInOrder(t *testing.T) {
	program := rewriteProgram(t, `{"body_rewrite":[
		"http-response ^http://example\\.test/ \"vip\":false \"vip\":true \"level\":\\d+ \"level\":9",
		"http-response-jq ^http://example\\.test/ '.source = \"B box\"'",
		"http-response-jq ^http://example\\.test/ '[broken'",
		{"name":"object","pattern":"^http://example\\.test/","phase":"response","jq":"del(.drop)"}]}`)
	request, _ := http.NewRequest("GET", "http://example.test/user", nil)
	response := localRewriteResponse(request, 200, make(http.Header), []byte(`{"vip":false,"level":1,"drop":1}`))
	var notes []string
	if err := program.response(request, response, "test", request.URL.String(), func(s string) { notes = append(notes, s) }); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	var value struct {
		VIP    bool   `json:"vip"`
		Level  int    `json:"level"`
		Source string `json:"source"`
		Drop   *int   `json:"drop"`
	}
	if err = json.Unmarshal(body, &value); err != nil || !value.VIP || value.Level != 9 || value.Source != "B box" || value.Drop != nil {
		t.Fatalf("body %s: %v", body, err)
	}
	if !strings.Contains(strings.Join(notes, " "), "jq skipped") {
		t.Fatalf("an invalid jq line was not reported: %v", notes)
	}
}
