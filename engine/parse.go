package engine

import (
	"bytes"
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

// ParseConfig parses a RouteWarden configuration from JSON or YAML data.
// It supports standalone JSON, standalone YAML (both camelCase and snake_case),
// and also unwraps embedded RouteWarden plugin definitions from Traefik dynamic YAML configurations.
func ParseConfig(data []byte) (*Config, error) {
	cfg := CreateConfig()
	if len(bytes.TrimSpace(data)) == 0 {
		return cfg, nil
	}

	// 1. Try standard JSON first
	if err := json.Unmarshal(data, cfg); err == nil {
		return cfg, nil
	}

	// 2. Parse as YAML
	var rawNode yaml.Node
	if err := yaml.Unmarshal(data, &rawNode); err != nil {
		return nil, fmt.Errorf("failed to parse configuration as JSON or YAML: %w", err)
	}

	var rawMap map[string]interface{}
	if err := rawNode.Decode(&rawMap); err != nil {
		return nil, fmt.Errorf("failed to decode YAML configuration: %w", err)
	}

	// 3. Check if wrapped in Traefik dynamic configuration
	// Format: http -> middlewares -> <name> -> plugin -> routewarden
	targetMap := rawMap
	if httpVal, ok := rawMap["http"].(map[string]interface{}); ok {
		if middlewaresVal, ok := httpVal["middlewares"].(map[string]interface{}); ok {
			for _, mVal := range middlewaresVal {
				if mObj, ok := mVal.(map[string]interface{}); ok {
					if pluginVal, ok := mObj["plugin"].(map[string]interface{}); ok {
						if rwVal, ok := pluginVal["routewarden"].(map[string]interface{}); ok {
							targetMap = rwVal
							break
						}
					}
				}
			}
		}
	}

	// 4. Convert targetMap into JSON bytes, then unmarshal into Config to honor json tags
	jsonBytes, err := json.Marshal(targetMap)
	if err != nil {
		return nil, fmt.Errorf("failed to convert YAML configuration to JSON: %w", err)
	}

	if err := json.Unmarshal(jsonBytes, cfg); err != nil {
		return nil, fmt.Errorf("failed to populate RouteWarden configuration: %w", err)
	}

	return cfg, nil
}
