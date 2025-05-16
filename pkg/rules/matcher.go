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
			continue
		}

		for _, matchArg := range rule.MatchArgs {
			for _, actualArg := range event.Args {
				if strings.Contains(actualArg, matchArg) {
					matched = append(matched, rule)
					break
				}
			}
		}
	}
	return matched
}
