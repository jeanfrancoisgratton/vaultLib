// vaultlib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: sys/mounts.go

package sys

import (
	"context"
	"fmt"
	"sort"
)

// ListMounts returns every secret engine mount in Vault, not only KV
// engines.
func (c *Client) ListMounts() ([]MountInfo, error) {
	return c.ListMountsContext(context.Background())
}

// ListMountsContext lists every secret engine mount using the supplied
// context.
func (c *Client) ListMountsContext(ctx context.Context) ([]MountInfo, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("vault client is nil")
	}

	raw, err := c.client.Sys().ListMountsWithContext(ctx)
	if err != nil {
		return nil, classifySysError(err, "list mounts")
	}

	mounts := make([]MountInfo, 0, len(raw))
	for path, m := range raw {
		if m == nil {
			continue
		}

		info := MountInfo{
			Path:            path,
			Type:            m.Type,
			Description:     m.Description,
			Accessor:        m.Accessor,
			Local:           m.Local,
			SealWrap:        m.SealWrap,
			Options:         m.Options,
			DefaultLeaseTTL: m.Config.DefaultLeaseTTL,
			MaxLeaseTTL:     m.Config.MaxLeaseTTL,
		}
		if m.Type == "kv" {
			info.KVVersion = m.Options["version"]
		}

		mounts = append(mounts, info)
	}

	sort.Slice(mounts, func(i, j int) bool { return mounts[i].Path < mounts[j].Path })
	return mounts, nil
}

// requireKVMount confirms the mount at path is a kv-type secrets engine
// before EditKVEngine or DisableKVEngine act on it. Both Tune and Unmount
// are generic calls that work against any mount type, so without this check
// a typo'd or misremembered path could silently tune or unmount an
// unrelated engine (e.g. database, pki) that happens to share the same
// generic endpoint with KV.
func (c *Client) requireKVMount(ctx context.Context, path, op string) error {
	mount, err := c.client.Sys().GetMountWithContext(ctx, path)
	if err != nil {
		return classifySysError(err, op)
	}
	if mount.Type != "kv" {
		return fmt.Errorf("%s failed: mount %q is type %q, not a kv engine", op, path, mount.Type)
	}
	return nil
}
