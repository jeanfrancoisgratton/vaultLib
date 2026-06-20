package shared

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Resolved returns a copy of Config with connection fields resolved from
// environment variables and standard Vault client files when they were not set
// explicitly.
func (c Config) Resolved() (Config, error) {
	resolved := c.trimmed()

	if resolved.Token == "" {
		resolved.Token = strings.TrimSpace(os.Getenv("VAULT_TOKEN"))
	}
	if resolved.Token == "" {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			data, err := os.ReadFile(filepath.Join(homeDir, ".vault-token"))
			if err == nil {
				resolved.Token = strings.TrimSpace(string(data))
			}
		}
	}
	if resolved.Token == "" {
		return Config{}, fmt.Errorf("vault token is missing: neither Config.Token, VAULT_TOKEN, nor ~/.vault-token provided a usable token")
	}

	if resolved.Address == "" {
		resolved.Address = strings.TrimSpace(os.Getenv("VAULT_ADDR"))
	}
	if resolved.Address == "" {
		return Config{}, fmt.Errorf("vault address is missing: neither Config.Address nor VAULT_ADDR provided a usable address")
	}

	if resolved.Namespace == "" {
		resolved.Namespace = strings.TrimSpace(os.Getenv("VAULT_NAMESPACE"))
	}
	if resolved.CACertPath == "" {
		resolved.CACertPath = strings.TrimSpace(os.Getenv("VAULT_CACERT"))
	}
	if resolved.CAPath == "" {
		resolved.CAPath = strings.TrimSpace(os.Getenv("VAULT_CAPATH"))
	}
	if resolved.ClientCertPath == "" {
		resolved.ClientCertPath = strings.TrimSpace(os.Getenv("VAULT_CLIENT_CERT"))
	}
	if resolved.ClientKeyPath == "" {
		resolved.ClientKeyPath = strings.TrimSpace(os.Getenv("VAULT_CLIENT_KEY"))
	}
	if resolved.TLSServerName == "" {
		resolved.TLSServerName = strings.TrimSpace(os.Getenv("VAULT_TLS_SERVER_NAME"))
	}
	if !resolved.TLSSkipVerify {
		resolved.TLSSkipVerify = envBool("VAULT_SKIP_VERIFY")
	}

	if resolved.MountPath == "" {
		return Config{}, fmt.Errorf("kv mount path is missing: Config.MountPath must point to a KV v2 mount")
	}

	return resolved, nil
}

// Resolved returns a copy of SystemConfig with connection fields resolved
// from environment variables and standard Vault client files when they were
// not set explicitly.
//
// Unlike Config.Resolved, a missing Token is not an error here: some
// operations built on SystemConfig (e.g. admin.SealStatus, admin.Unseal) are
// unauthenticated by design. Callers whose operation does require a token are
// left to fail at the API call itself, which returns a clear "unauthorized"
// error.
func (c SystemConfig) Resolved() (SystemConfig, error) {
	resolved := c.trimmed()

	if resolved.Token == "" {
		resolved.Token = strings.TrimSpace(os.Getenv("VAULT_TOKEN"))
	}
	if resolved.Token == "" {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			data, err := os.ReadFile(filepath.Join(homeDir, ".vault-token"))
			if err == nil {
				resolved.Token = strings.TrimSpace(string(data))
			}
		}
	}

	if resolved.Address == "" {
		resolved.Address = strings.TrimSpace(os.Getenv("VAULT_ADDR"))
	}
	if resolved.Address == "" {
		return SystemConfig{}, fmt.Errorf("vault address is missing: neither SystemConfig.Address nor VAULT_ADDR provided a usable address")
	}

	if resolved.Namespace == "" {
		resolved.Namespace = strings.TrimSpace(os.Getenv("VAULT_NAMESPACE"))
	}
	if resolved.CACertPath == "" {
		resolved.CACertPath = strings.TrimSpace(os.Getenv("VAULT_CACERT"))
	}
	if resolved.CAPath == "" {
		resolved.CAPath = strings.TrimSpace(os.Getenv("VAULT_CAPATH"))
	}
	if resolved.ClientCertPath == "" {
		resolved.ClientCertPath = strings.TrimSpace(os.Getenv("VAULT_CLIENT_CERT"))
	}
	if resolved.ClientKeyPath == "" {
		resolved.ClientKeyPath = strings.TrimSpace(os.Getenv("VAULT_CLIENT_KEY"))
	}
	if resolved.TLSServerName == "" {
		resolved.TLSServerName = strings.TrimSpace(os.Getenv("VAULT_TLS_SERVER_NAME"))
	}
	if !resolved.TLSSkipVerify {
		resolved.TLSSkipVerify = envBool("VAULT_SKIP_VERIFY")
	}

	return resolved, nil
}

func (c SystemConfig) trimmed() SystemConfig {
	c.Address = strings.TrimSpace(c.Address)
	c.Token = strings.TrimSpace(c.Token)
	c.Namespace = strings.Trim(strings.TrimSpace(c.Namespace), "/")
	c.CACertPath = strings.TrimSpace(c.CACertPath)
	c.CAPath = strings.TrimSpace(c.CAPath)
	c.ClientCertPath = strings.TrimSpace(c.ClientCertPath)
	c.ClientKeyPath = strings.TrimSpace(c.ClientKeyPath)
	c.TLSServerName = strings.TrimSpace(c.TLSServerName)
	return c
}

func (c Config) trimmed() Config {
	c.Address = strings.TrimSpace(c.Address)
	c.Token = strings.TrimSpace(c.Token)
	c.MountPath = strings.Trim(strings.TrimSpace(c.MountPath), "/")
	c.Namespace = strings.Trim(strings.TrimSpace(c.Namespace), "/")
	c.CACertPath = strings.TrimSpace(c.CACertPath)
	c.CAPath = strings.TrimSpace(c.CAPath)
	c.ClientCertPath = strings.TrimSpace(c.ClientCertPath)
	c.ClientKeyPath = strings.TrimSpace(c.ClientKeyPath)
	c.TLSServerName = strings.TrimSpace(c.TLSServerName)
	return c
}

func envBool(name string) bool {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return false
	}

	parsed, err := strconv.ParseBool(raw)
	if err == nil {
		return parsed
	}

	switch strings.ToLower(raw) {
	case "1", "yes", "y", "on":
		return true
	default:
		return false
	}
}
