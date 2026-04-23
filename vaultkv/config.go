package vaultkv

import (
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Address   string
	Token     string
	MountPath string
}

func (c Config) Resolved() (Config, *Error) {
	resolved := c

	if strings.TrimSpace(resolved.Token) == "" {
		resolved.Token = strings.TrimSpace(os.Getenv("VAULT_TOKEN"))
	}
	if strings.TrimSpace(resolved.Token) == "" {
		if homeDir, err := os.UserHomeDir(); err == nil {
			if data, err := os.ReadFile(filepath.Join(homeDir, ".vault-token")); err == nil {
				resolved.Token = strings.TrimSpace(string(data))
			}
		}
	}
	if strings.TrimSpace(resolved.Token) == "" {
		return Config{}, newError(
			ErrVaultAuthTokenMissing,
			"Vault token is missing",
			"neither Config.Token, VAULT_TOKEN, nor ~/.vault-token provided a usable token",
			nil,
		)
	}

	if strings.TrimSpace(resolved.Address) == "" {
		resolved.Address = strings.TrimSpace(os.Getenv("VAULT_ADDR"))
	}
	if strings.TrimSpace(resolved.Address) == "" {
		return Config{}, newError(
			ErrVaultServerAddressMissing,
			"Vault address is missing",
			"neither Config.Address nor VAULT_ADDR provided a usable address",
			nil,
		)
	}

	resolved.MountPath = strings.Trim(resolved.MountPath, "/")
	if resolved.MountPath == "" {
		return Config{}, newError(
			ErrInvalidPath,
			"KV mount path is missing",
			"Config.MountPath must point to a KV v2 mount",
			nil,
		)
	}

	return resolved, nil
}
