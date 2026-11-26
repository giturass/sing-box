package libbox

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type modulePanel struct {
	ModuleID       string `json:"moduleId"`
	Name           string `json:"name"`
	Title          string `json:"title,omitempty"`
	Content        string `json:"content,omitempty"`
	Style          string `json:"style,omitempty"`
	Icon           string `json:"icon,omitempty"`
	IconColor      string `json:"icon-color,omitempty"`
	Script         string `json:"script,omitempty"`
	Index          int    `json:"index"`
	UpdateInterval int32  `json:"updateInterval,omitempty"`
	line           moduleLine
}

var panelColor = regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`)

func parseModulePanel(text string) (modulePanel, error) {
	name, options, found := strings.Cut(text, "=")
	panel := modulePanel{Name: strings.TrimSpace(name), Index: -1, line: moduleLine{Text: text}}
	fields, valid := moduleFields(options, false)
	if !found || !valid || panel.Name == "" {
		return panel, fmt.Errorf("invalid panel declaration")
	}
	for _, field := range fields {
		key, value, found := strings.Cut(field, "=")
		if !found {
			return panel, fmt.Errorf("invalid panel field: %s", field)
		}
		value = moduleUnquote(strings.TrimSpace(value))
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "title":
			panel.Title = value
		case "content":
			panel.Content = strings.ReplaceAll(value, `\n`, "\n")
		case "style":
			if value != "good" && value != "info" && value != "alert" && value != "error" {
				return panel, fmt.Errorf("invalid panel style: %s", value)
			}
			panel.Style = value
		case "icon":
			panel.Icon = value
		case "icon-color":
			if !panelColor.MatchString(value) {
				return panel, fmt.Errorf("invalid panel icon color")
			}
			panel.IconColor = value
		case "script-name":
			panel.Script = value
		case "update-interval":
			seconds, err := strconv.ParseInt(value, 10, 32)
			if err != nil || seconds < 0 {
				return panel, fmt.Errorf("invalid panel update interval")
			}
			panel.UpdateInterval = int32(seconds)
		default:
			return panel, fmt.Errorf("unsupported panel field: %s", key)
		}
	}
	if panel.Title == "" && panel.Content == "" && panel.Script == "" {
		return panel, fmt.Errorf("panel needs a title, content or generic script")
	}
	return panel, nil
}

func (description *moduleDescription) resolvePanels(moduleID string, pending []modulePanel) {
	if len(pending) == 0 {
		return
	}
	indices := make(map[string]int)
	for index, value := range description.values["generic"] {
		name := value.(moduleObject)["name"].(string)
		if _, exists := indices[name]; exists {
			index = -1
		}
		indices[name] = index
	}
	seen := make(map[string]bool)
	for _, panel := range pending {
		panel.ModuleID = moduleID
		line := panel.line
		if seen[panel.Name] {
			line.Issue = "duplicate panel name: " + panel.Name
		} else if panel.Script != "" {
			index, found := indices[panel.Script]
			if !found || index < 0 {
				line.Issue = "missing or ambiguous generic panel script: " + panel.Script
			} else {
				panel.Index = index
			}
		}
		if line.Issue != "" {
			description.Lines["ignored"] = append(description.Lines["ignored"], line)
			continue
		}
		seen[panel.Name] = true
		description.Lines["panel"] = append(description.Lines["panel"], line)
		description.Panels = append(description.Panels, panel)
	}
}

func DescribeProfileSurgePanels(content string) (string, error) {
	panels := []modulePanel{}
	_, err := expandModuleConfig(baseContext(nil), content, &panels)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(panels)
	return string(data), err
}
