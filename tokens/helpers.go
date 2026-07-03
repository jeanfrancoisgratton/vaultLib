// vaultlib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: tokens/helpers.go

package tokens

import (
	"encoding/json"
	"strconv"

	"github.com/hashicorp/vault/api"
)

// Token lookup responses (auth/token/lookup, lookup-self, lookup-accessor)
// return Secret.Data as a generic map[string]interface{}, unlike create and
// renew which populate the typed Secret.Auth struct. The helpers below
// extract individual fields with the same manual type-switch approach
// already used in kv/read.go (extractVersion) and kv/write.go
// (currentVersion), rather than introducing a struct-decoding dependency
// like mapstructure.

func dataString(data map[string]interface{}, key string) string {
	v, ok := data[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func dataBool(data map[string]interface{}, key string) bool {
	v, ok := data[key]
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}

func dataInt64(data map[string]interface{}, key string) int64 {
	v, ok := data[key]
	if !ok {
		return 0
	}
	switch t := v.(type) {
	case int64:
		return t
	case int:
		return int64(t)
	case int32:
		return int64(t)
	case float64:
		return int64(t)
	case json.Number:
		i, err := t.Int64()
		if err == nil {
			return i
		}
	case string:
		i, err := strconv.ParseInt(t, 10, 64)
		if err == nil {
			return i
		}
	}
	return 0
}

func dataInt(data map[string]interface{}, key string) int {
	return int(dataInt64(data, key))
}

func dataStringSlice(data map[string]interface{}, key string) []string {
	v, ok := data[key]
	if !ok || v == nil {
		return nil
	}
	switch t := v.(type) {
	case []string:
		return t
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func dataStringMap(data map[string]interface{}, key string) map[string]string {
	v, ok := data[key]
	if !ok || v == nil {
		return nil
	}
	raw, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, val := range raw {
		if s, ok := val.(string); ok {
			out[k] = s
		}
	}
	return out
}

// parseTokenInfo normalizes a lookup-style Secret (lookup, lookup-self,
// lookup-accessor) into a TokenInfo. "meta" is used for the metadata key
// rather than "metadata", matching Vault's actual token lookup response
// shape (which differs from the auth block's "metadata" key used on
// create/renew).
func parseTokenInfo(secret *api.Secret) *TokenInfo {
	if secret == nil || secret.Data == nil {
		return nil
	}
	data := secret.Data

	return &TokenInfo{
		ID:             dataString(data, "id"),
		Accessor:       dataString(data, "accessor"),
		CreationTime:   dataInt64(data, "creation_time"),
		CreationTTL:    dataInt64(data, "creation_ttl"),
		TTL:            dataInt64(data, "ttl"),
		ExplicitMaxTTL: dataInt64(data, "explicit_max_ttl"),
		ExpireTime:     dataString(data, "expire_time"),
		IssueTime:      dataString(data, "issue_time"),
		DisplayName:    dataString(data, "display_name"),
		EntityID:       dataString(data, "entity_id"),
		Policies:       dataStringSlice(data, "policies"),
		Meta:           dataStringMap(data, "meta"),
		NumUses:        dataInt(data, "num_uses"),
		Orphan:         dataBool(data, "orphan"),
		Renewable:      dataBool(data, "renewable"),
		Path:           dataString(data, "path"),
		Type:           dataString(data, "type"),
	}
}

// parseTokenAuth normalizes the auth block of a create/renew Secret into a
// TokenAuth. Unlike parseTokenInfo, this reads from the typed
// Secret.Auth struct rather than the generic Data map, since create and
// renew responses populate Auth directly.
func parseTokenAuth(secret *api.Secret) *TokenAuth {
	if secret == nil || secret.Auth == nil {
		return nil
	}
	auth := secret.Auth

	return &TokenAuth{
		ClientToken:   auth.ClientToken,
		Accessor:      auth.Accessor,
		Policies:      auth.Policies,
		TokenPolicies: auth.TokenPolicies,
		Metadata:      auth.Metadata,
		LeaseDuration: auth.LeaseDuration,
		Renewable:     auth.Renewable,
		EntityID:      auth.EntityID,
		Orphan:        auth.Orphan,
	}
}
