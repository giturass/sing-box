package option

import (
	"fmt"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/httpdebug"
)

func (o Options) ScriptDeclarations() (*httpdebug.ScriptDeclarations, error) {
	names := &httpdebug.ScriptDeclarations{Rule: make(map[string]bool), DNS: make(map[string]bool)}
	if o.Experimental != nil {
		if scripts := o.Experimental.Scripts; scripts != nil {
			for _, script := range scripts.Rule {
				names.Rule[script.Name] = true
			}
			for _, script := range scripts.DNS {
				names.DNS[script.Name] = true
			}
		}
		if err := httpdebug.ValidateDNSHosts(o.Experimental.DNSHosts); err != nil {
			return nil, err
		}
		for _, host := range o.Experimental.DNSHosts {
			if host.Script != "" && !names.DNS[host.Script] {
				return nil, fmt.Errorf("DNS script %q is not configured", host.Script)
			}
		}
	}
	validate := func(name string, requiresResolve bool) error {
		if name == "" && requiresResolve {
			return fmt.Errorf("script_requires_resolve requires a script condition")
		}
		if name != "" && !names.Rule[name] {
			return fmt.Errorf("rule script %q is not configured", name)
		}
		return nil
	}
	var route func(Rule) error
	route = func(rule Rule) error {
		if rule.Type == C.RuleTypeLogical {
			for _, child := range rule.LogicalOptions.Rules {
				if err := route(child); err != nil {
					return err
				}
			}
			return nil
		}
		return validate(rule.DefaultOptions.Script, rule.DefaultOptions.ScriptRequiresResolve)
	}
	var headless func(HeadlessRule) error
	headless = func(rule HeadlessRule) error {
		if rule.Type == C.RuleTypeLogical {
			for _, child := range rule.LogicalOptions.Rules {
				if err := headless(child); err != nil {
					return err
				}
			}
			return nil
		}
		return validate(rule.DefaultOptions.Script, rule.DefaultOptions.ScriptRequiresResolve)
	}
	if o.Route != nil {
		for _, rule := range o.Route.Rules {
			if err := route(rule); err != nil {
				return nil, err
			}
		}
		for _, set := range o.Route.RuleSet {
			if set.Type == C.RuleSetTypeInline {
				for _, rule := range set.InlineOptions.Rules {
					if err := headless(rule); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	return names, nil
}
