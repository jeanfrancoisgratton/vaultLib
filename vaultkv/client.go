package vaultkv

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"
)

type ReadOptions struct {
	Version int
	Field   string
}

type Secret struct {
	MountPath        string                 `json:"mountPath"`
	Path             string                 `json:"path"`
	RequestedVersion int                    `json:"requestedVersion,omitempty"`
	Version          int                    `json:"version,omitempty"`
	Data             map[string]interface{} `json:"data"`
}

type Client struct {
	cfg    Config
	client *api.Client
}

func NewClient(cfg Config) (*Client, *Error) {
	resolved, cerr := cfg.Resolved()
	if cerr != nil {
		return nil, cerr
	}

	apiClient, err := api.NewClient(&api.Config{Address: resolved.Address})
	if err != nil {
		return nil, newError(ErrVaultInit, "Vault client creation failed", err.Error(), err)
	}
	apiClient.SetToken(resolved.Token)

	return &Client{cfg: resolved, client: apiClient}, nil
}

func ReadSecret(cfg Config, secretPath string, opts ReadOptions) (*Secret, *Error) {
	client, cerr := NewClient(cfg)
	if cerr != nil {
		return nil, cerr
	}
	return client.ReadSecret(secretPath, opts)
}

func ReadSecretField(cfg Config, secretPath, field string, version int) (interface{}, *Error) {
	client, cerr := NewClient(cfg)
	if cerr != nil {
		return nil, cerr
	}
	return client.ReadSecretField(secretPath, field, version)
}

func (c *Client) ReadSecret(secretPath string, opts ReadOptions) (*Secret, *Error) {
	path := strings.Trim(secretPath, "/")
	if path == "" {
		return nil, newError(ErrInvalidPath, "Invalid secret path", "secret path cannot be empty", nil)
	}

	dataPath := fmt.Sprintf("%s/data/%s", c.cfg.MountPath, path)
	metaPath := fmt.Sprintf("%s/metadata/%s", c.cfg.MountPath, path)

	meta, err := c.client.Logical().Read(metaPath)
	if err != nil {
		return nil, classifyReadError(err, true)
	}
	if meta == nil {
		return nil, newError(ErrInvalidPath, "Secret path does not exist", fmt.Sprintf("metadata path %s returned nil", metaPath), nil)
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
				return nil, newError(ErrReadSecret, "ReadSecret failed", "all the secret's versions were destroyed", nil)
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
		return nil, newError(ErrReadSecret, "ReadSecret failed", "secret read returned nil", nil)
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, newError(ErrExtractData, "ReadSecret failed", "secret format is invalid", nil)
	}

	if actualVersion == 0 {
		actualVersion = extractVersion(secret)
	}

	if opts.Field != "" {
		if _, found := data[opts.Field]; !found {
			return nil, newError(ErrFieldNotFound, "ReadSecret error", fmt.Sprintf("field %s not found", opts.Field), nil)
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

func (c *Client) ReadSecretField(secretPath, field string, version int) (interface{}, *Error) {
	secret, cerr := c.ReadSecret(secretPath, ReadOptions{Version: version, Field: field})
	if cerr != nil {
		return nil, cerr
	}
	val, ok := secret.Data[field]
	if !ok {
		return nil, newError(ErrFieldNotFound, "ReadSecret error", fmt.Sprintf("field %s not found", field), nil)
	}
	return val, nil
}

func findLatestAvailableVersion(meta *api.Secret) (int, *Error) {
	if meta == nil {
		return 0, newError(ErrReadSecret, "Unable to fetch metadata", "metadata response is nil", nil)
	}

	rawVersions, ok := meta.Data["versions"].(map[string]interface{})
	if !ok {
		return 0, newError(ErrReadSecret, "Version metadata not found", "metadata did not include a versions map", nil)
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

func classifyReadError(err error, metadataPhase bool) *Error {
	if err == nil {
		return nil
	}
	msg := err.Error()

	switch {
	case strings.Contains(msg, "connection refused"), strings.Contains(msg, "no such host"):
		return newError(ErrVaultUnavailable, "Vault service unavailable", msg, err)
	case strings.Contains(msg, "permission denied"), strings.Contains(msg, "unauthorized"):
		return newError(ErrVaultInvalidAuth, "Invalid Vault token or unauthorized", msg, err)
	case strings.Contains(msg, "Vault is sealed"), strings.Contains(msg, "server is sealed"):
		return newError(ErrVaultSealed, "Vault is sealed", msg, err)
	default:
		if metadataPhase {
			return newError(ErrInvalidPath, "Secret path does not exist or metadata read failed", msg, err)
		}
		return newError(ErrReadSecret, "ReadSecret failed", msg, err)
	}
}
