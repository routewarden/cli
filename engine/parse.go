package engine

import (
	"bytes"
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

func unwrapConfigMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return m
	}
	// Case 1: Traefik dynamic configuration (http -> middlewares -> <name> -> plugin -> routewarden)
	if httpVal, ok := m["http"].(map[string]interface{}); ok {
		if middlewaresVal, ok := httpVal["middlewares"].(map[string]interface{}); ok {
			for _, mVal := range middlewaresVal {
				if mObj, ok := mVal.(map[string]interface{}); ok {
					if pluginVal, ok := mObj["plugin"].(map[string]interface{}); ok {
						if rwVal, ok := pluginVal["routewarden"].(map[string]interface{}); ok {
							return rwVal
						}
					}
				}
			}
		}
	}
	// Case 2: Traefik middlewares root (middlewares -> <name> -> plugin -> routewarden)
	if middlewaresVal, ok := m["middlewares"].(map[string]interface{}); ok {
		for _, mVal := range middlewaresVal {
			if mObj, ok := mVal.(map[string]interface{}); ok {
				if pluginVal, ok := mObj["plugin"].(map[string]interface{}); ok {
					if rwVal, ok := pluginVal["routewarden"].(map[string]interface{}); ok {
						return rwVal
					}
				}
			}
		}
	}
	// Case 3: plugin -> routewarden
	if pluginVal, ok := m["plugin"].(map[string]interface{}); ok {
		if rwVal, ok := pluginVal["routewarden"].(map[string]interface{}); ok {
			return rwVal
		}
	}
	// Case 4: routewarden or routeWarden root key (Helm values, wrapped YAML/JSON)
	if rwVal, ok := m["routewarden"].(map[string]interface{}); ok {
		return rwVal
	}
	if rwVal, ok := m["routeWarden"].(map[string]interface{}); ok {
		return rwVal
	}
	return m
}

// ParseConfig parses a RouteWarden configuration from JSON or YAML data.
// It supports standalone JSON, standalone YAML (both camelCase and snake_case),
// and unwraps embedded RouteWarden definitions from Traefik dynamic YAML, Helm charts, and plugin definitions.
func ParseConfig(data []byte) (*Config, error) {
	cfg := CreateConfig()
	if len(bytes.TrimSpace(data)) == 0 {
		return cfg, nil
	}

	// 1. Try standard JSON first (unwrapping any root envelope like "routewarden": { ... })
	var rawJSON map[string]interface{}
	if err := json.Unmarshal(data, &rawJSON); err == nil && rawJSON != nil {
		targetMap := unwrapConfigMap(rawJSON)
		jsonBytes, err := json.Marshal(targetMap)
		if err == nil {
			if err := json.Unmarshal(jsonBytes, cfg); err == nil {
				return cfg, nil
			}
		}
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

	// 3. Unwrap if wrapped in Traefik, Helm, or plugin root keys
	targetMap := unwrapConfigMap(rawMap)

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

