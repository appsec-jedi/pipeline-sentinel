package logging

import (
	"encoding/json"
	"os"

	"github.com/appsec-jedi/pipeline-sentinel/pkg/events"
)

func WriteDetectionsToFile(detections []events.Detection, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	return encoder.Encode(detections)
}
