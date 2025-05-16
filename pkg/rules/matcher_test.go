package rules

import (
	"testing"

	"github.com/appsec-jedi/pipeline-sentinel/pkg/events"
)

func TestMatchRules(t *testing.T) {
	rules := []Rule{
		{ID: "curl_test", MatchCommand: "curl", Severity: "high"},
	}
	event := events.CommandEvent{
		Command: "curl",
		Args:    []string{"http://example.com"},
	}

	matches := MatchRules(event, rules)
	if len(matches) != 1 {
		t.Errorf("expected 1 match, got %d", len(matches))
	}
}
