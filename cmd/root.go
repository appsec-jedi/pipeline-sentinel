/*
Copyright © 2025 Jake Jacobs-Smith - AppSec-Jedi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/appsec-jedi/pipeline-sentinel/pkg/events"
	"github.com/appsec-jedi/pipeline-sentinel/pkg/logging"
	"github.com/appsec-jedi/pipeline-sentinel/pkg/rules"
)

// rootCmd represents the base command when called without any subcommands
var (
	cfgFile string
	rootCmd = &cobra.Command{
		Use:   "pipeline-sentinel",
		Short: "Pipeline Sentinel watches for suspicious activity in CI/CD jobs",
		Run: func(cmd *cobra.Command, args []string) {
			var allDetections []events.Detection
			color.Green("Pipeline Sentinel agent started.")
			fmt.Println("Loaded config from:", viper.ConfigFileUsed())
			rulesPath := "config/rules.yaml"
			ruleSet, err := rules.LoadRulesFromFile(rulesPath)
			if err != nil {
				color.Red("Failed to load rules: %v", err)
				os.Exit(1)
			}

			color.Yellow("📋 Loaded %d rules", len(ruleSet.Rules))
			for _, rule := range ruleSet.Rules {
				fmt.Printf("→ [%s] %s: %s (match: '%s')\n",
					rule.Severity, rule.ID, rule.Description, rule.MatchCommand)
			}
			jobSteps := [][]string{
				{"echo", "Hello, world!"},
				{"curl", "http://malicious.site"},
				{"python", "-c", "import os"},
				{"ls", "-la"},
			}
			for _, step := range jobSteps {
				cmd := step[0]
				args := step[1:]

				event, err := events.RunAndCapture(cmd, args...)
				if err != nil {
					color.Yellow("Command failed: %v", err)
					continue
				}

				color.Blue("Ran: %s %v", event.Command, event.Args)

				matches := rules.MatchRules(event, ruleSet.Rules)
				if len(matches) > 0 {
					color.Red("Suspicious command detected!")
					for _, match := range matches {
						fmt.Printf("→ [%s] %s: %s\n", match.Severity, match.ID, match.Description)
					}
				} else {
					color.Green("Command passed: No matches.")
				}
				for _, match := range matches {
					detection := events.Detection{
						Timestamp:   event.Timestamp,
						Command:     event.Command,
						Args:        event.Args,
						MatchedRule: match.ID,
						Severity:    match.Severity,
					}
					allDetections = append(allDetections, detection)
				}
			}
			err = logging.WriteDetectionsToFile(allDetections, "detections.json")
			if err != nil {
				color.Red("❌ Failed to write detections to file: %v", err)
			} else {
				color.Green("📁 Detections saved to detections.json")
			}
		},
	}
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "config/config.yaml", "config file (default is config.yaml)")
	viper.SetDefault("log.level", "info")
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath(".")
		viper.SetConfigName("config")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		color.Blue("📘 Using config file: %s", viper.ConfigFileUsed())
	} else {
		color.Red("⚠️  Could not read config: %s", err)
	}
}
