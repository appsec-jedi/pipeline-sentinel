package events

import "time"

type CommandEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Command   string    `json:"command"`
	Args      []string  `json:"args"`
}
