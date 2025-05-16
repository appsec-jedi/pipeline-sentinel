package events

import (
	"os/exec"
	"time"
)

func RunAndCapture(cmdName string, args ...string) (CommandEvent, error) {
	cmd := exec.Command(cmdName, args...)

	err := cmd.Run()

	event := CommandEvent{
		Timestamp: time.Now(),
		Command:   cmdName,
		Args:      args,
	}

	return event, err
}
