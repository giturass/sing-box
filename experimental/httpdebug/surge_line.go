package httpdebug

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/schema"
)

// A rewrite list item is either the B-box object or one line in the syntax of
// the matching Surge profile section. A line is kept as written when the
// profile is formatted; only the object form carries name, match and disabled.

type bodyReplace struct{ regex, replacement string }

var mapLocalKeys = []string{"data-type", "data", "status-code", "header", "update-interval"}

func surgeField(line string) (field, rest string) {
	line = strings.TrimLeft(line, " \t")
	end := strings.IndexAny(line, " \t")
	if end < 0 {
		return line, ""
	}
	return line[:end], strings.TrimLeft(line[end:], " \t")
}

// ruleLine reports whether a list item is written as a profile line.
func ruleLine(data []byte) (string, bool, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '"' {
		return "", false, nil
	}
	var line string
	if err := json.Unmarshal(data, &line); err != nil {
		return "", true, err
	}
	line = strings.TrimSpace(line)
	if line == "" || strings.ContainsAny(line, "\r\n") {
		return "", true, errors.New("a rule line must be one non-empty line")
	}
	return line, true, nil
}

func decodeRuleObject(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

func ruleSchema(builder schema.Builder, name string, rule reflect.Type) (*schema.Node, error) {
	return builder.Define(name, func() (*schema.Node, error) {
		node := schema.StrictObject()
		if err := builder.FlattenStruct(node, rule); err != nil {
			return nil, err
		}
		return schema.OneOf(schema.StringNode(), node), nil
	})
}

// [Body Rewrite]: http-request|http-response <url-regex> <regex> <replacement> ...
// or http-request-jq|http-response-jq <url-regex> <jq-expression>.
func parseBodyRewriteLine(line string) (BodyRewrite, error) {
	kind, rest := surgeField(line)
	rule := BodyRewrite{line: line}
	switch strings.TrimSuffix(kind, "-jq") {
	case "http-request":
		rule.Phase = "request"
	case "http-response":
		rule.Phase = "response"
	default:
		return rule, errors.New("a body rewrite line starts with http-request, http-response, http-request-jq or http-response-jq")
	}
	rule.Pattern, rest = surgeField(rest)
	if strings.HasSuffix(kind, "-jq") {
		// jq has no single-quoted strings, so one enclosing pair is the
		// quoting of the line and not part of the expression.
		expression := rest
		if n := len(expression); n >= 2 && expression[0] == '\'' && expression[n-1] == '\'' {
			expression = expression[1 : n-1]
		}
		if strings.TrimSpace(expression) == "" {
			return rule, errors.New("a jq body rewrite line is <type> <url-regex> <jq-expression>")
		}
		rule.JQ = &expression
		return rule, nil
	}
	// A regex or replacement holding a space needs the object form.
	fields := strings.Fields(rest)
	if len(fields) == 0 || len(fields)%2 != 0 {
		return rule, errors.New("a body rewrite line is <type> <url-regex> followed by <regex> <replacement> pairs")
	}
	rule.Regex, rule.Replacement = fields[0], fields[1]
	for i := 2; i < len(fields); i += 2 {
		rule.more = append(rule.more, bodyReplace{fields[i], fields[i+1]})
	}
	return rule, nil
}

// [URL Rewrite]: <url-regex> <replacement> [header|302|307|reject].
func parseURLRewriteLine(line string) (URLRewrite, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 || len(fields) > 3 {
		return URLRewrite{}, errors.New("a URL rewrite line is <url-regex> <replacement> [header|302|307|reject]")
	}
	rule := URLRewrite{RewriteMatch: RewriteMatch{Pattern: fields[0]}, Action: "header", Replacement: fields[1], line: line}
	if len(fields) == 3 {
		rule.Action = fields[2]
	}
	return rule, nil
}

// [Header Rewrite]: [http-request|http-response] <url-regex> <action> <field> [value] [template].
func parseHeaderRewriteLine(line string) (HeaderRewrite, error) {
	rule := HeaderRewrite{Phase: "request", line: line}
	first, rest := surgeField(line)
	switch first {
	case "http-request":
		first, rest = surgeField(rest)
	case "http-response":
		rule.Phase = "response"
		first, rest = surgeField(rest)
	}
	rule.Pattern = first
	action, rest := surgeField(rest)
	rule.Header, rest = surgeField(rest)
	valid := rule.Header != ""
	switch action {
	case "header-add":
		rule.Operation, rule.Value = "add", rest
		valid = valid && rest != ""
	case "header-del":
		rule.Operation = "delete"
		valid = valid && rest == ""
	case "header-replace":
		rule.Operation, rule.Value = "replace", rest
		valid = valid && rest != ""
	case "header-replace-regex":
		rule.Operation = "replace_regex"
		rule.Regex, rule.Replacement = surgeField(rest)
		valid = valid && rule.Regex != ""
	default:
		return rule, errors.New("a header rewrite action is header-add, header-del, header-replace or header-replace-regex")
	}
	if !valid {
		return rule, errors.New("a header rewrite line is [http-request|http-response] <url-regex> <action> <field> [value] [template]")
	}
	return rule, nil
}

// A quoted value ends at the quote before the next parameter or the line end,
// so JSON text may hold quotes and spaces of its own.
func mapLocalValueEnd(value string) int {
	for i := 1; i < len(value); i++ {
		if value[i] != '"' {
			continue
		}
		rest := strings.TrimLeft(value[i+1:], " \t")
		if rest == "" {
			return i
		}
		if len(rest) == len(value)-i-1 {
			continue
		}
		for _, key := range mapLocalKeys {
			if strings.HasPrefix(rest, key+"=") {
				return i
			}
		}
	}
	return -1
}

func parseMapLocalHeaders(value string) ([]Header, error) {
	separator := "|"
	if !strings.Contains(value, ":") {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, errors.New("header is neither name:value pairs nor Base64 header lines")
		}
		value, separator = strings.ReplaceAll(string(decoded), "\r\n", "\n"), "\n"
	}
	var headers []Header
	for _, item := range strings.Split(value, separator) {
		if strings.TrimSpace(item) == "" {
			continue
		}
		name, content, found := strings.Cut(item, ":")
		if !found {
			return nil, fmt.Errorf("header %q has no value", item)
		}
		headers = append(headers, Header{Name: strings.TrimSpace(name), Value: strings.TrimSpace(content)})
	}
	return headers, nil
}

// [Map Local]: <url-regex> data-type= data= status-code= header= update-interval=.
func parseMapLocalLine(line string) (MapLocal, error) {
	// Surge reads a file when data-type is omitted.
	rule := MapLocal{DataType: "file", line: line}
	var rest string
	rule.Pattern, rest = surgeField(line)
	for rest != "" {
		key, value, found := strings.Cut(rest, "=")
		if !found || key == "" || strings.ContainsAny(key, " \t") {
			return rule, errors.New("a map local line is <url-regex> followed by key=value parameters")
		}
		if strings.HasPrefix(value, `"`) {
			end := mapLocalValueEnd(value)
			if end < 0 {
				return rule, fmt.Errorf("%s has an unterminated quoted value", key)
			}
			value, rest = value[1:end], strings.TrimLeft(value[end+1:], " \t")
		} else {
			value, rest = surgeField(value)
		}
		var err error
		switch key {
		case "data-type":
			rule.DataType = value
		case "data":
			rule.Data = value
		case "status-code":
			rule.Status, err = strconv.Atoi(value)
		case "header":
			rule.Headers, err = parseMapLocalHeaders(value)
		case "update-interval":
			rule.UpdateInterval, err = strconv.ParseInt(value, 10, 64)
		default:
			err = errors.New("unknown parameter")
		}
		if err != nil {
			return rule, fmt.Errorf("%s: %w", key, err)
		}
	}
	return rule, nil
}

func (r *BodyRewrite) UnmarshalJSON(data []byte) error {
	line, found, err := ruleLine(data)
	if found {
		if err == nil {
			*r, err = parseBodyRewriteLine(line)
		}
		return err
	}
	type plain BodyRewrite
	var value plain
	if err = decodeRuleObject(data, &value); err != nil {
		return err
	}
	*r = BodyRewrite(value)
	return nil
}

func (r BodyRewrite) MarshalJSON() ([]byte, error) {
	if r.line != "" {
		return json.Marshal(r.line)
	}
	type plain BodyRewrite
	return json.Marshal(plain(r))
}

func (BodyRewrite) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return ruleSchema(builder, "HTTPBodyRewrite", reflect.TypeFor[BodyRewrite]())
}

func (r *URLRewrite) UnmarshalJSON(data []byte) error {
	line, found, err := ruleLine(data)
	if found {
		if err == nil {
			*r, err = parseURLRewriteLine(line)
		}
		return err
	}
	type plain URLRewrite
	var value plain
	if err = decodeRuleObject(data, &value); err != nil {
		return err
	}
	*r = URLRewrite(value)
	return nil
}

func (r URLRewrite) MarshalJSON() ([]byte, error) {
	if r.line != "" {
		return json.Marshal(r.line)
	}
	type plain URLRewrite
	return json.Marshal(plain(r))
}

func (URLRewrite) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return ruleSchema(builder, "HTTPURLRewrite", reflect.TypeFor[URLRewrite]())
}

func (r *HeaderRewrite) UnmarshalJSON(data []byte) error {
	line, found, err := ruleLine(data)
	if found {
		if err == nil {
			*r, err = parseHeaderRewriteLine(line)
		}
		return err
	}
	type plain HeaderRewrite
	var value plain
	if err = decodeRuleObject(data, &value); err != nil {
		return err
	}
	*r = HeaderRewrite(value)
	return nil
}

func (r HeaderRewrite) MarshalJSON() ([]byte, error) {
	if r.line != "" {
		return json.Marshal(r.line)
	}
	type plain HeaderRewrite
	return json.Marshal(plain(r))
}

func (HeaderRewrite) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return ruleSchema(builder, "HTTPHeaderRewrite", reflect.TypeFor[HeaderRewrite]())
}

func (r *MapLocal) UnmarshalJSON(data []byte) error {
	line, found, err := ruleLine(data)
	if found {
		if err == nil {
			*r, err = parseMapLocalLine(line)
		}
		return err
	}
	type plain MapLocal
	var value plain
	if err = decodeRuleObject(data, &value); err != nil {
		return err
	}
	*r = MapLocal(value)
	return nil
}

func (r MapLocal) MarshalJSON() ([]byte, error) {
	if r.line != "" {
		return json.Marshal(r.line)
	}
	type plain MapLocal
	return json.Marshal(plain(r))
}

func (MapLocal) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return ruleSchema(builder, "HTTPMapLocal", reflect.TypeFor[MapLocal]())
}
