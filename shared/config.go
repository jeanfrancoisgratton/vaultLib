package shared

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Resolved returns a copy of Config with token and address resolved from the
// environment when they were not set explicitly.
func (c Config) Resolved() (Config, error) {
	resolved := c

	if strings.TrimSpace(resolved.Token) == "" {
		resolved.Token = strings.TrimSpace(os.Getenv("VAULT_TOKEN"))
	}
	if strings.TrimSpace(resolved.Token) == "" {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			data, err := os.ReadFile(filepath.Join(homeDir, ".vault-token"))
			if err == nil {
				resolved.Token = strings.TrimSpace(string(data))
			}
		}
	}
	if strings.TrimSpace(resolved.Token) == "" {
		return Config{}, fmt.Errorf("vault token is missing: neither Config.Token, VAULT_TOKEN, nor ~/.vault-token provided a usable token")
	}

	if strings.TrimSpace(resolved.Address) == "" {
		resolved.Address = strings.TrimSpace(os.Getenv("VAULT_ADDR"))
	}
	if strings.TrimSpace(resolved.Address) == "" {
		return Config{}, fmt.Errorf("vault address is missing: neither Config.Address nor VAULT_ADDR provided a usable address")
	}

	resolved.MountPath = strings.Trim(resolved.MountPath, "/")
	return resolved, nil
}
