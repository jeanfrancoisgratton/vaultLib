// vaultLib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: kv/read.go

package kv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"
)

// ReadSecret reads a Vault KV secret. It supports both KV v1 and KV v2; the
// engine version is detected automatically at client construction time.
func (c *Client) ReadSecret(secretPath string, opts ReadOptions) (*Secret, error) {
	return c.ReadSecretContext(context.Background(), secretPath, opts)
}

// ReadSecretContext reads a Vault KV secret using the supplied context.
func (c *Client) ReadSecretContext(ctx context.Context, secretPath string, opts ReadOptions) (*Secret, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("vault client is nil")
	}
	if err := validateReadOptions(opts); err != nil {
		return nil, err
	}

	path := strings.Trim(secretPath, "/")
	if path == "" {
		return nil, fmt.Errorf("invalid secret path: secret path cannot be empty")
	}

	requestedVersion := opts.Version
	actualVersion := 0

	var (
		secret *api.Secret
		err    error
	)

	if c.kvVersion == 1 {
		apiPath := fmt.Sprintf("%s/%s", c.cfg.MountPath, path)
		secret, err = c.client.Logical().ReadWithContext(ctx, apiPath)
	} else {
		dataPath := fmt.Sprintf("%s/data/%s", c.cfg.MountPath, path)
		secret, err = c.readKVv2Data(ctx, dataPath, opts.Version)
	}
	if err != nil {
		return nil, classifyReadError(err, false)
	}

	if secret == nil && c.kvVersion == 2 && opts.Version == 0 && opts.FallbackToLatestAvailable {
		fallbackVersion, err := c.findLatestAvailableVersion(ctx, path)
		if err != nil {
			return nil, err
		}
		if fallbackVersion == 0 {
			return nil, fmt.Errorf("read secret failed: no non-deleted secret version is available for %q", path)
		}

		dataPath := fmt.Sprintf("%s/data/%s", c.cfg.MountPath, path)
		secret, err = c.readKVv2Data(ctx, dataPath, fallbackVersion)
		if err != nil {
			return nil, classifyReadError(err, false)
		}
		actualVersion = fallbackVersion
	}

	if secret == nil {
		return nil, fmt.Errorf("read secret failed: secret %q was not found or the requested version is deleted", path)
	}

	// KV v1: data lives directly at secret.Data.
	if c.kvVersion == 1 {
		return &Secret{
			MountPath:        c.cfg.MountPath,
			Path:             path,
			RequestedVersion: requestedVersion,
			Data:             secret.Data,
		}, nil
	}

	// KV v2: data is nested under secret.Data["data"].
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("read secret failed: secret format is invalid")
	}

	if actualVersion == 0 {
		actualVersion = extractVersion(secret)
	}
	if actualVersion == 0 && opts.Version > 0 {
		actualVersion = opts.Version
	}

	return &Secret{
		MountPath:        c.cfg.MountPath,
		Path:             path,
		RequestedVersion: requestedVersion,
		Version:          actualVersion,
		Data:             data,
	}, nil
}

// ReadSecretField reads a single field from a Vault KV secret. Version 0
// means latest. Version is ignored for KV v1.
func (c *Client) ReadSecretField(secretPath, field string, version int) (interface{}, error) {
	return c.ReadSecretFieldContext(context.Background(), secretPath, field, version)
}

// ReadSecretFieldContext reads a single field from a Vault KV secret using
// the supplied context. Version 0 means latest.
func (c *Client) ReadSecretFieldContext(ctx context.Context, secretPath, field string, version int) (interface{}, error) {
	field = strings.TrimSpace(field)
	if field == "" {
		return nil, fmt.Errorf("invalid field: field cannot be empty")
	}

	secret, err := c.ReadSecretContext(ctx, secretPath, ReadOptions{Version: version})
	if err != nil {
		return nil, err
	}

	val, ok := secret.Data[field]
	if !ok {
		return nil, fmt.Errorf("read secret field failed: field %q not found", field)
	}
	return val, nil
}

func validateReadOptions(opts ReadOptions) error {
	if opts.Version < 0 {
		return fmt.Errorf("invalid version: version cannot be negative")
	}
	if opts.Version > 0 && opts.FallbackToLatestAvailable {
		return fmt.Errorf("invalid read options: FallbackToLatestAvailable is only valid when Version is 0")
	}
	return nil
}

func (c *Client) readKVv2Data(ctx context.Context, dataPath string, version int) (*api.Secret, error) {
	if version > 0 {
		return c.client.Logical().ReadWithDataWithContext(ctx, dataPath, map[string][]string{
			"version": {strconv.Itoa(version)},
		})
	}
	return c.client.Logical().ReadWithContext(ctx, dataPath)
}

func (c *Client) findLatestAvailableVersion(ctx context.Context, secretPath string) (int, error) {
	metaPath := fmt.Sprintf("%s/metadata/%s", c.cfg.MountPath, strings.Trim(secretPath, "/"))

	meta, err := c.client.Logical().ReadWithContext(ctx, metaPath)
	if err != nil {
		return 0, classifyReadError(err, true)
	}
	if meta == nil {
		return 0, fmt.Errorf("secret path does not exist: metadata path %s returned nil", metaPath)
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
		if deletionTime, _ := vmeta["deletion_time"].(string); strings.TrimSpace(deletionTime) != "" {
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

	if responseErr, ok := errors.AsType[*api.ResponseError](err); ok {
		switch responseErr.StatusCode {
		case http.StatusBadRequest:
			return fmt.Errorf("vault rejected the KV read request: %w", err)
		case http.StatusForbidden, http.StatusUnauthorized:
			return fmt.Errorf("invalid Vault token or unauthorized: %w", err)
		case http.StatusNotFound:
			if metadataPhase {
				return fmt.Errorf("secret path does not exist or metadata read is unauthorized: %w", err)
			}
			return fmt.Errorf("secret path does not exist or requested version is unavailable: %w", err)
		case http.StatusServiceUnavailable:
			return fmt.Errorf("vault is sealed or unavailable: %w", err)
		default:
			if metadataPhase {
				return fmt.Errorf("metadata read failed: %w", err)
			}
			return fmt.Errorf("read secret failed: %w", err)
		}
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
			return fmt.Errorf("metadata read failed: %w", err)
		}
		return fmt.Errorf("read secret failed: %w", err)
	}
}
