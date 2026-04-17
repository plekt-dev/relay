// Package config loads plekt-relay runtime settings from a YAML file.
//
// The file replaces the previous set of MC_* environment variables.
// See config.example.yml at the repo root for the supported keys.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Addr          string        `yaml:"addr"`
	WebhookSecret string        `yaml:"webhook_secret"`
	ClaudeBin     string        `yaml:"claude_bin"`
	ClaudeArgs    []string      `yaml:"claude_args"`
	RunTimeout    time.Duration `yaml:"run_timeout"`
}

type rawConfig struct {
	Addr          string      `yaml:"addr"`
	WebhookSecret string      `yaml:"webhook_secret"`
	ClaudeBin     string      `yaml:"claude_bin"`
	ClaudeArgs    interface{} `yaml:"claude_args"`
	RunTimeout    string      `yaml:"run_timeout"`
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var r rawConfig
	if err := yaml.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	cfg := &Config{
		Addr:          firstNonEmpty(r.Addr, ":8765"),
		WebhookSecret: strings.TrimSpace(r.WebhookSecret),
		ClaudeBin:     firstNonEmpty(r.ClaudeBin, "claude"),
		ClaudeArgs:    parseArgs(r.ClaudeArgs),
		RunTimeout:    parseDuration(r.RunTimeout, 5*time.Minute),
	}
	if cfg.WebhookSecret == "" {
		return nil, fmt.Errorf("%s: webhook_secret is required", path)
	}
	return cfg, nil
}

func firstNonEmpty(v, fallback string) string {
	if s := strings.TrimSpace(v); s != "" {
		return s
	}
	return fallback
}

func parseArgs(v interface{}) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		return strings.Fields(t)
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func parseDuration(s string, fallback time.Duration) time.Duration {
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}
