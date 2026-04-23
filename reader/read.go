// vaultLib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: reader/read.go
// Original timestamp: 2026/04/23 14:34:20

package reader

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"
)

func (c *Client) ReadSecret(secretPath string, opts ReadOptions) (*Secret, error) {
	path := strings.Trim(secretPath, "/")
	if path == "" {
		return nil, fmt.Errorf("invalid secret path: secret path cannot be empty")
	}

	dataPath := fmt.Sprintf("%s/data/%s", c.cfg.MountPath, path)
	metaPath := fmt.Sprintf("%s/metadata/%s", c.cfg.MountPath, path)

	meta, err := c.client.Logical().Read(metaPath)
	if err != nil {
		return nil, classifyReadError(err, true)
	}
	if meta == nil {
		return nil, fmt.Errorf("secret path does not exist: metadata path %s returned nil", metaPath)
	}

	var secret *api.Secret
	requestedVersion := opts.Version
	actualVersion := 0

	if opts.Version > 0 {
		secret, err = c.client.Logical().ReadWithData(dataPath, map[string][]string{
			"version": {strconv.Itoa(opts.Version)},
		})
		actualVersion = opts.Version
	} else {
		secret, err = c.client.Logical().Read(dataPath)
		if err == nil && secret == nil {
			fallbackVersion, ferr := findLatestAvailableVersion(meta)
			if ferr != nil {
				return nil, ferr
			}
			if fallbackVersion == 0 {
				return nil, fmt.Errorf("read secret failed: all secret versions were destroyed")
			}
			secret, err = c.client.Logical().ReadWithData(dataPath, map[string][]string{
				"version": {strconv.Itoa(fallbackVersion)},
			})
			actualVersion = fallbackVersion
		}
	}

	if err != nil {
		return nil, classifyReadError(err, false)
	}
	if secret == nil {
		return nil, fmt.Errorf("read secret failed: secret read returned nil")
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("read secret failed: secret format is invalid")
	}

	if actualVersion == 0 {
		actualVersion = extractVersion(secret)
	}

	if opts.Field != "" {
		if _, found := data[opts.Field]; !found {
			return nil, fmt.Errorf("read secret error: field %s not found", opts.Field)
		}
	}

	return &Secret{
		MountPath:        c.cfg.MountPath,
		Path:             path,
		RequestedVersion: requestedVersion,
		Version:          actualVersion,
		Data:             data,
	}, nil
}

func (c *Client) ReadSecretField(secretPath, field string, version int) (interface{}, error) {
	secret, err := c.ReadSecret(secretPath, ReadOptions{Version: version, Field: field})
	if err != nil {
		return nil, err
	}

	val, ok := secret.Data[field]
	if !ok {
		return nil, fmt.Errorf("read secret error: field %s not found", field)
	}
	return val, nil
}

func findLatestAvailableVersion(meta *api.Secret) (int, error) {
	if meta == nil {
		return 0, fmt.Errorf("unable to fetch metadata: metadata response is nil")
	}

	rawVersions, ok := meta.Data["versions"].(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("version metadata not found: metadata did not include a versions map")
	}

	available := make([]int, 0, len(rawVersions))
	for verStr, vmetaAny := range rawVersions {
		vmeta, ok := vmetaAny.(map[string]interface{})
		if !ok {
			continue
		}
		if destroyed, _ := vmeta["destroyed"].(bool); destroyed {
			continue
		}
		if ver, err := strconv.Atoi(verStr); err == nil {
			available = append(available, ver)
		}
	}

	if len(available) == 0 {
		return 0, nil
	}

	sort.Sort(sort.Reverse(sort.IntSlice(available)))
	return available[0], nil
}

func extractVersion(secret *api.Secret) int {
	if secret == nil {
		return 0
	}
	meta, ok := secret.Data["metadata"].(map[string]interface{})
	if !ok {
		return 0
	}
	versionAny, found := meta["version"]
	if !found {
		return 0
	}

	switch v := versionAny.(type) {
	case int:
		return v
	case int32:
		return int(v)
	case int64:
		return int(v)
	case float64:
		return int(v)
	case json.Number:
		i, err := strconv.Atoi(v.String())
		if err == nil {
			return i
		}
	case string:
		i, err := strconv.Atoi(v)
		if err == nil {
			return i
		}
	}
	return 0
}

func classifyReadError(err error, metadataPhase bool) error {
	if err == nil {
		return nil
	}

	msg := err.Error()

	switch {
	case strings.Contains(msg, "connection refused"), strings.Contains(msg, "no such host"):
		return fmt.Errorf("vault service unavailable: %w", err)
	case strings.Contains(msg, "permission denied"), strings.Contains(msg, "unauthorized"):
		return fmt.Errorf("invalid Vault token or unauthorized: %w", err)
	case strings.Contains(msg, "Vault is sealed"), strings.Contains(msg, "server is sealed"):
		return fmt.Errorf("vault is sealed: %w", err)
	default:
		if metadataPhase {
			return fmt.Errorf("secret path does not exist or metadata read failed: %w", err)
		}
		return fmt.Errorf("read secret failed: %w", err)
	}
}
