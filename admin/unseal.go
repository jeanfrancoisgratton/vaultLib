// vaultLib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: admin/unseal.go

package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/vault/api"
)

// Unseal submits each key in keys to the Vault unseal endpoint in order,
// stopping as soon as the vault reports it is unsealed. Each submission
// produces one UnsealResult entry, so the caller can observe progress toward
// the unseal threshold.
//
// Keys are provided by the caller: vaultlib never reads key material from
// disk or from environment variables on the caller's behalf.
//
// If the vault is already unsealed when Unseal is called, a single
// UnsealResult with Sealed=false and Progress=0 is returned immediately
// without submitting any keys.
//
// Errors from individual key submissions are returned immediately, leaving
// the unseal sequence in whatever partial state the vault is in at that point.
// The caller can inspect the returned results to determine how many keys were
// accepted before the failure.
func (c *Client) Unseal(keys []string) ([]UnsealResult, error) {
	return c.UnsealContext(context.Background(), keys)
}

// UnsealContext submits unseal keys using the supplied context.
func (c *Client) UnsealContext(ctx context.Context, keys []string) ([]UnsealResult, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("vault client is nil")
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("unseal failed: keys slice must not be empty")
	}

	// Check current seal status first; avoid submitting keys unnecessarily.
	status, err := c.client.Sys().SealStatusWithContext(ctx)
	if err != nil {
		return nil, classifyAdminError(err, "unseal status check")
	}
	if !status.Sealed {
		return []UnsealResult{{
			KeyIndex:  -1,
			Sealed:    false,
			Progress:  0,
			Threshold: status.T,
		}}, nil
	}

	results := make([]UnsealResult, 0, len(keys))

	for i, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			return results, fmt.Errorf("unseal failed: key at index %d is empty", i)
		}

		resp, err := c.client.Sys().UnsealWithContext(ctx, key)
		if err != nil {
			return results, classifyAdminError(err, fmt.Sprintf("unseal key %d", i))
		}

		results = append(results, UnsealResult{
			KeyIndex:  i,
			Sealed:    resp.Sealed,
			Progress:  resp.Progress,
			Threshold: resp.T,
		})

		if !resp.Sealed {
			// Threshold reached; no need to submit further keys.
			break
		}
	}

	return results, nil
}

// classifyAdminError maps a raw Vault API error to a descriptive admin-scoped
// error message.
func classifyAdminError(err error, op string) error {
	if err == nil {
		return nil
	}

	if responseErr, ok := errors.AsType[*api.ResponseError](err); ok {
		switch responseErr.StatusCode {
		case http.StatusBadRequest:
			return fmt.Errorf("%s failed: vault rejected the request (invalid unseal key format): %w", op, err)
		case http.StatusForbidden, http.StatusUnauthorized:
			return fmt.Errorf("%s failed: unauthorized — check token and namespace: %w", op, err)
		case http.StatusServiceUnavailable:
			return fmt.Errorf("%s failed: vault is unavailable: %w", op, err)
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
		return fmt.Errorf("%s failed: unauthorized — check token and namespace: %w", op, err)
	case strings.Contains(msg, "Vault is sealed"), strings.Contains(msg, "server is sealed"):
		return fmt.Errorf("%s failed: vault is sealed: %w", op, err)
	default:
		return fmt.Errorf("%s failed: %w", op, err)
	}
}
