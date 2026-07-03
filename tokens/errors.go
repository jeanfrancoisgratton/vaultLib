// vaultlib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: tokens/errors.go

package tokens

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/vault/api"
)

// classifyTokenError maps a raw Vault API error to a descriptive, op-scoped
// error message. One classifier serves create, lookup, renew, revoke, and
// list-accessors, mirroring the single classifier used in policies.
func classifyTokenError(err error, op string) error {
	if err == nil {
		return nil
	}

	if responseErr, ok := errors.AsType[*api.ResponseError](err); ok {
		switch responseErr.StatusCode {
		case http.StatusBadRequest:
			return fmt.Errorf("%s failed: vault rejected the request (check token options or accessor/token value): %w", op, err)
		case http.StatusForbidden, http.StatusUnauthorized:
			return fmt.Errorf("%s failed: invalid Vault token or insufficient policy: %w", op, err)
		case http.StatusNotFound:
			return fmt.Errorf("%s failed: token or accessor does not exist: %w", op, err)
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
