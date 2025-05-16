package rules

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func LoadRulesFromFile(path string) (RuleSet, error) {
	var rules RuleSet

	data, err := os.ReadFile(path)
	if err != nil {
		return rules, fmt.Errorf("error reading rules file: %w", err)
	}

	err = yaml.Unmarshal(data, &rules)
	if err != nil {
		return rules, fmt.Errorf("error parsing YAML: %w", err)
	}

	return rules, nil
}
