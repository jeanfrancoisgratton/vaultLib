// vaultlib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: kv/write.go

package kv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"
)

// WriteSecret writes a full secret to the given path, creating it if it does
// not exist. For KV v2, each call produces a new version. For KV v1, the
// secret is overwritten in place.
//
// Use WriteSecretField to add or replace a single field without touching the
// rest of the secret.
func (c *Client) WriteSecret(secretPath string, data map[string]interface{}, opts WriteOptions) (*WriteResult, error) {
	return c.WriteSecretContext(context.Background(), secretPath, data, opts)
}

// WriteSecretContext writes a full secret using the supplied context.
func (c *Client) WriteSecretContext(ctx context.Context, secretPath string, data map[string]interface{}, opts WriteOptions) (*WriteResult, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("vault client is nil")
	}

	path := strings.Trim(secretPath, "/")
	if path == "" {
		return nil, fmt.Errorf("invalid secret path: secret path cannot be empty")
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("invalid secret data: data map cannot be empty or nil")
	}

	var (
		apiPath string
		body    map[string]interface{}
	)

	if c.kvVersion == 1 {
		apiPath = fmt.Sprintf("%s/%s", c.cfg.MountPath, path)
		body = data
	} else {
		apiPath = fmt.Sprintf("%s/data/%s", c.cfg.MountPath, path)
		body = map[string]interface{}{"data": data}
		if opts.EnableCAS {
			body["options"] = map[string]interface{}{"cas": opts.CASVersion}
		}
	}

	secret, err := c.client.Logical().WriteWithContext(ctx, apiPath, body)
	if err != nil {
		return nil, classifyWriteError(err, "write secret")
	}

	result := &WriteResult{
		MountPath: c.cfg.MountPath,
		Path:      path,
	}
	if c.kvVersion == 2 && secret != nil {
		result.Version = extractWriteVersion(secret)
	}
	return result, nil
}

// WriteSecretField upserts a single field in a secret at the given path. If
// the secret does not exist it is created with only the supplied field. If the
// secret already exists the field is added or overwritten while all other
// fields are preserved. For KV v2, this produces a new version.
//
// WriteSecretField is a read-modify-write operation and is therefore subject
// to a TOCTOU race. Use WriteSecretContext with EnableCAS when strict
// consistency is required.
func (c *Client) WriteSecretField(secretPath, field string, value interface{}) (*WriteResult, error) {
	return c.WriteSecretFieldContext(context.Background(), secretPath, field, value)
}

// WriteSecretFieldContext upserts a single field using the supplied context.
func (c *Client) WriteSecretFieldContext(ctx context.Context, secretPath, field string, value interface{}) (*WriteResult, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("vault client is nil")
	}

	field = strings.TrimSpace(field)
	if field == "" {
		return nil, fmt.Errorf("invalid field: field name cannot be empty")
	}
	path := strings.Trim(secretPath, "/")
	if path == "" {
		return nil, fmt.Errorf("invalid secret path: secret path cannot be empty")
	}

	data, err := c.readCurrentData(ctx, path)
	if err != nil {
		return nil, err
	}
	if data == nil {
		data = make(map[string]interface{})
	}
	data[field] = value

	return c.WriteSecretContext(ctx, path, data, WriteOptions{})
}

// DeleteSecretField removes a single field from an existing secret. For KV v2
// this produces a new version with the field absent. Returns an error if the
// secret or the field does not exist.
//
// Like WriteSecretField, this is a read-modify-write operation subject to
// TOCTOU races.
func (c *Client) DeleteSecretField(secretPath, field string) (*WriteResult, error) {
	return c.DeleteSecretFieldContext(context.Background(), secretPath, field)
}

// DeleteSecretFieldContext removes a single field using the supplied context.
func (c *Client) DeleteSecretFieldContext(ctx context.Context, secretPath, field string) (*WriteResult, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("vault client is nil")
	}

	field = strings.TrimSpace(field)
	if field == "" {
		return nil, fmt.Errorf("invalid field: field name cannot be empty")
	}
	path := strings.Trim(secretPath, "/")
	if path == "" {
		return nil, fmt.Errorf("invalid secret path: secret path cannot be empty")
	}

	data, err := c.readCurrentData(ctx, path)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fmt.Errorf("delete secret field failed: secret %q does not exist", path)
	}
	if _, ok := data[field]; !ok {
		return nil, fmt.Errorf("delete secret field failed: field %q not found in secret %q", field, path)
	}

	delete(data, field)

	return c.WriteSecretContext(ctx, path, data, WriteOptions{})
}

// DeleteSecret permanently erases a secret and, for KV v2, all of its versions.
//
// For KV v2, this deletes the secret's metadata path, which removes every
// version and the path itself in a single irreversible operation. Use
// DestroySecret to permanently remove only a specific version while keeping
// the path and any remaining versions intact.
//
// For KV v1, the secret key is deleted directly.
func (c *Client) DeleteSecret(secretPath string) error {
	return c.DeleteSecretContext(context.Background(), secretPath)
}

// DeleteSecretContext erases a secret using the supplied context.
func (c *Client) DeleteSecretContext(ctx context.Context, secretPath string) error {
	if c == nil || c.client == nil {
		return fmt.Errorf("vault client is nil")
	}

	path := strings.Trim(secretPath, "/")
	if path == "" {
		return fmt.Errorf("invalid secret path: secret path cannot be empty")
	}

	var apiPath string
	if c.kvVersion == 1 {
		apiPath = fmt.Sprintf("%s/%s", c.cfg.MountPath, path)
	} else {
		// Deleting the metadata path removes all versions and the path itself.
		apiPath = fmt.Sprintf("%s/metadata/%s", c.cfg.MountPath, path)
	}

	_, err := c.client.Logical().DeleteWithContext(ctx, apiPath)
	if err != nil {
		return classifyWriteError(err, "delete secret")
	}
	return nil
}

// SoftDeleteSecret performs a KV v2 soft-delete on one or more specific
// versions of a secret. Soft-deleted versions can be recovered with an
// undelete operation. opts.Versions lists the versions to soft-delete; an
// empty or nil slice soft-deletes the latest version.
//
// For KV v1, which has no versioning, SoftDeleteSecret behaves like
// DeleteSecret and opts.Versions is ignored.
func (c *Client) SoftDeleteSecret(secretPath string, opts DeleteOptions) error {
	return c.SoftDeleteSecretContext(context.Background(), secretPath, opts)
}

// SoftDeleteSecretContext soft-deletes secret versions using the supplied context.
func (c *Client) SoftDeleteSecretContext(ctx context.Context, secretPath string, opts DeleteOptions) error {
	if c == nil || c.client == nil {
		return fmt.Errorf("vault client is nil")
	}

	path := strings.Trim(secretPath, "/")
	if path == "" {
		return fmt.Errorf("invalid secret path: secret path cannot be empty")
	}

	// KV v1 has no versioning; fall back to a full permanent delete.
	if c.kvVersion == 1 {
		return c.DeleteSecretContext(ctx, path)
	}

	versions := opts.Versions
	if len(versions) == 0 {
		// No explicit version: soft-delete the latest version.
		latest, err := c.currentVersion(ctx, path)
		if err != nil {
			return err
		}
		versions = []int{latest}
	}

	apiPath := fmt.Sprintf("%s/delete/%s", c.cfg.MountPath, path)
	body := map[string]interface{}{"versions": versions}

	_, err := c.client.Logical().WriteWithContext(ctx, apiPath, body)
	if err != nil {
		return classifyWriteError(err, "soft-delete secret")
	}
	return nil
}

// DestroySecret permanently destroys a specific KV v2 secret version.
// opts.Version selects the version; a value of 0 destroys the latest version.
// Unlike DeleteSecret, the secret path and any other versions are left intact.
//
// For KV v1, which does not support versioning, DestroySecret behaves like
// DeleteSecret and opts.Version is ignored.
func (c *Client) DestroySecret(secretPath string, opts DestroyOptions) error {
	return c.DestroySecretContext(context.Background(), secretPath, opts)
}

// DestroySecretContext permanently destroys a secret version using the
// supplied context.
func (c *Client) DestroySecretContext(ctx context.Context, secretPath string, opts DestroyOptions) error {
	if c == nil || c.client == nil {
		return fmt.Errorf("vault client is nil")
	}
	if opts.Version < 0 {
		return fmt.Errorf("invalid version: version cannot be negative")
	}

	path := strings.Trim(secretPath, "/")
	if path == "" {
		return fmt.Errorf("invalid secret path: secret path cannot be empty")
	}

	// KV v1 has no versioning; fall back to a full permanent delete.
	if c.kvVersion == 1 {
		return c.DeleteSecretContext(ctx, path)
	}

	version := opts.Version
	if version == 0 {
		var err error
		version, err = c.currentVersion(ctx, path)
		if err != nil {
			return err
		}
	}

	apiPath := fmt.Sprintf("%s/destroy/%s", c.cfg.MountPath, path)
	body := map[string]interface{}{"versions": []int{version}}

	_, err := c.client.Logical().WriteWithContext(ctx, apiPath, body)
	if err != nil {
		return classifyWriteError(err, "destroy secret")
	}
	return nil
}

// UpdateSecretField checks whether the given field exists in the current
// version of the secret. If the field is absent it returns an error, leaving
// the secret unchanged. If the field is present it writes a new version with
// the updated value, preserving all other fields.
//
// Like WriteSecretField, this is a read-modify-write operation subject to
// TOCTOU races.
func (c *Client) UpdateSecretField(secretPath, field string, value interface{}) (*WriteResult, error) {
	return c.UpdateSecretFieldContext(context.Background(), secretPath, field, value)
}

// UpdateSecretFieldContext checks and updates a field using the supplied context.
func (c *Client) UpdateSecretFieldContext(ctx context.Context, secretPath, field string, value interface{}) (*WriteResult, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("vault client is nil")
	}

	field = strings.TrimSpace(field)
	if field == "" {
		return nil, fmt.Errorf("invalid field: field name cannot be empty")
	}
	path := strings.Trim(secretPath, "/")
	if path == "" {
		return nil, fmt.Errorf("invalid secret path: secret path cannot be empty")
	}

	data, err := c.readCurrentData(ctx, path)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fmt.Errorf("update secret field failed: secret %q does not exist", path)
	}
	if _, ok := data[field]; !ok {
		return nil, fmt.Errorf("update secret field failed: field %q not found in secret %q; use WriteSecretField to create it", field, path)
	}

	data[field] = value
	return c.WriteSecretContext(ctx, path, data, WriteOptions{})
}

// -------------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------------

// readCurrentData reads the latest data map for the given path. It returns
// (nil, nil) when the secret does not exist or when its latest version is
// soft-deleted or destroyed. It is used internally for read-modify-write
// operations.
func (c *Client) readCurrentData(ctx context.Context, path string) (map[string]interface{}, error) {
	var apiPath string
	if c.kvVersion == 1 {
		apiPath = fmt.Sprintf("%s/%s", c.cfg.MountPath, path)
	} else {
		apiPath = fmt.Sprintf("%s/data/%s", c.cfg.MountPath, path)
	}

	secret, err := c.client.Logical().ReadWithContext(ctx, apiPath)
	if err != nil {
		// A 404 on a KV read means the secret path does not exist; return nil
		// so the caller can decide whether to create it or to return an error.
		if responseErr, ok := errors.AsType[*api.ResponseError](err); ok && responseErr.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, classifyWriteError(err, "read current secret data")
	}
	if secret == nil {
		return nil, nil
	}

	if c.kvVersion == 1 {
		return secret.Data, nil
	}

	// For KV v2, data.data is nil when the latest version is soft-deleted or
	// destroyed. Treat that the same as not found so the caller can decide.
	data, _ := secret.Data["data"].(map[string]interface{})
	return data, nil
}

// currentVersion queries the KV v2 metadata path to find the current
// (latest) version number of the secret.
func (c *Client) currentVersion(ctx context.Context, path string) (int, error) {
	metaPath := fmt.Sprintf("%s/metadata/%s", c.cfg.MountPath, path)

	meta, err := c.client.Logical().ReadWithContext(ctx, metaPath)
	if err != nil {
		return 0, classifyWriteError(err, "read secret metadata")
	}
	if meta == nil {
		return 0, fmt.Errorf("destroy secret failed: secret %q does not exist", path)
	}

	switch v := meta.Data["current_version"].(type) {
	case int:
		return v, nil
	case int32:
		return int(v), nil
	case int64:
		return int(v), nil
	case float64:
		return int(v), nil
	case json.Number:
		i, err := strconv.Atoi(v.String())
		if err != nil {
			return 0, fmt.Errorf("destroy secret failed: could not parse current_version for %q: %w", path, err)
		}
		return i, nil
	case string:
		i, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("destroy secret failed: could not parse current_version for %q: %w", path, err)
		}
		return i, nil
	}
	return 0, fmt.Errorf("destroy secret failed: current_version not found in metadata for %q", path)
}

// extractWriteVersion extracts the version number from a KV v2 write response.
func extractWriteVersion(secret *api.Secret) int {
	if secret == nil {
		return 0
	}
	// The Vault KV v2 write response nests version info under "data".
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		data = secret.Data
	}
	switch v := data["version"].(type) {
	case int:
		return v
	case int32:
		return int(v)
	case int64:
		return int(v)
	case float64:
		return int(v)
	case json.Number:
		i, _ := strconv.Atoi(v.String())
		return i
	case string:
		i, _ := strconv.Atoi(v)
		return i
	}
	return 0
}

// classifyWriteError maps a raw Vault API error to a descriptive error with
// clear attribution of sealed vaults, authentication failures, policy issues,
// and CAS conflicts.
func classifyWriteError(err error, op string) error {
	if err == nil {
		return nil
	}

	if responseErr, ok := errors.AsType[*api.ResponseError](err); ok {
		switch responseErr.StatusCode {
		case http.StatusBadRequest:
			// Vault returns 400 for CAS mismatches and invalid request bodies.
			return fmt.Errorf("%s failed: vault rejected the request (check CAS version or KV engine configuration): %w", op, err)
		case http.StatusForbidden, http.StatusUnauthorized:
			return fmt.Errorf("%s failed: invalid Vault token or insufficient policy: %w", op, err)
		case http.StatusNotFound:
			return fmt.Errorf("%s failed: secret path does not exist or is unauthorized: %w", op, err)
		case http.StatusServiceUnavailable:
			return fmt.Errorf("%s failed: vault is sealed or unavailable: %w", op, err)
		case http.StatusTooManyRequests:
			return fmt.Errorf("%s failed: vault rate limit exceeded: %w", op, err)
		default:
			return fmt.Errorf("%s failed: %w", op, err)
		}
	}

	msg := err.Error()
	switch {
	case strings.Contains(msg, "connection refused"), strings.Contains(msg, "no such host"):
		return fmt.Errorf("%s failed: vault service unreachable: %w", op, err)
	case strings.Contains(msg, "permission denied"), strings.Contains(msg, "unauthorized"):
		return fmt.Errorf("%s failed: invalid Vault token or insufficient policy: %w", op, err)
	case strings.Contains(msg, "Vault is sealed"), strings.Contains(msg, "server is sealed"):
		return fmt.Errorf("%s failed: vault is sealed: %w", op, err)
	default:
		return fmt.Errorf("%s failed: %w", op, err)
	}
}
