package rules

import (
	"strings"

	"github.com/appsec-jedi/pipeline-sentinel/pkg/events"
)

func MatchRules(event events.CommandEvent, rules []Rule) []Rule {
	var matched []Rule
	for _, rule := range rules {
		if strings.Contains(event.Command, rule.MatchCommand) {
			matched = append(matched, rule)
		}
	}
	return matched
}
