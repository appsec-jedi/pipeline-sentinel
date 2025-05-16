package rules

type Rule struct {
	ID           string `yaml:"id"`
	Description  string `yaml:"description"`
	MatchCommand string `yaml:"match_command"`
	Severity     string `yaml:"severity"`
}

type RuleSet struct {
	Rules []Rule `yaml:"rules"`
}
