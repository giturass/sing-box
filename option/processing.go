package option

import (
	"reflect"

	"github.com/sagernet/sing-box/experimental/httpdebug"
	"github.com/sagernet/sing-box/schema"
)

// Validation lives with the processing engine; the core owns schema generation.
type HTTPRoutingOptions httpdebug.HTTPRoutingConfig

func (o *HTTPRoutingOptions) UnmarshalJSON(data []byte) error {
	return (*httpdebug.HTTPRoutingConfig)(o).UnmarshalJSON(data)
}

func (o HTTPRoutingOptions) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	node := schema.StrictObject()
	if err := builder.FlattenStruct(node, reflect.TypeFor[HTTPRoutingOptions]()); err != nil {
		return nil, err
	}
	return node, nil
}

type HTTPRewriteOptions httpdebug.RewriteConfig

func (o *HTTPRewriteOptions) UnmarshalJSON(data []byte) error {
	return (*httpdebug.RewriteConfig)(o).UnmarshalJSON(data)
}

func (o HTTPRewriteOptions) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	node := schema.StrictObject()
	err := builder.FlattenStruct(node, reflect.TypeFor[HTTPRewriteOptions]())
	if err != nil {
		return nil, err
	}
	return node, nil
}

type MITMOptions httpdebug.MITMConfig

func (o *MITMOptions) UnmarshalJSON(data []byte) error {
	return (*httpdebug.MITMConfig)(o).UnmarshalJSON(data)
}
func (o MITMOptions) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	node := schema.StrictObject()
	if err := builder.FlattenStruct(node, reflect.TypeFor[MITMOptions]()); err != nil {
		return nil, err
	}
	return node, nil
}

type ScriptsOptions httpdebug.ScriptsConfig

func (o *ScriptsOptions) UnmarshalJSON(data []byte) error {
	return (*httpdebug.ScriptsConfig)(o).UnmarshalJSON(data)
}
func (o ScriptsOptions) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	node := schema.StrictObject()
	if err := builder.FlattenStruct(node, reflect.TypeFor[ScriptsOptions]()); err != nil {
		return nil, err
	}
	return node, nil
}

// ModuleOptions holds one Surge module beside the profile it extends. The
// profile keeps the module text; libbox adds what an enabled module contributes
// when the profile is checked or started, and never writes it back.
type ModuleOptions struct {
	ID          string            `json:"id,omitempty"`
	Name        string            `json:"name,omitempty"`
	URL         string            `json:"url,omitempty"`
	Enabled     bool              `json:"enabled,omitempty"`
	Content     string            `json:"content,omitempty"`
	Arguments   map[string]string `json:"arguments,omitempty"`
	Attachments map[string]string `json:"attachments,omitempty"`
	UpdatedAt   int64             `json:"updated_at,omitempty"`
}
