package events

import "time"

type Detection struct {
	Timestamp   time.Time `json:"timestamp"`
	Command     string    `json:"command"`
	Args        []string  `json:"args"`
	MatchedRule string    `json:"matched_rule"`
	Severity    string    `json:"severity"`
}
