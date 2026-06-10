// vaultLib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: admin/sealstatus.go

package admin

import (
	"context"
	"fmt"
)

// SealStatus queries the Vault seal-status endpoint (GET /v1/sys/seal-status)
// and returns the current seal configuration. No token is required; this
// endpoint is unauthenticated.
func (c *Client) SealStatus() (*SealStatusResult, error) {
	return c.SealStatusContext(context.Background())
}

// SealStatusContext queries the Vault seal-status endpoint using the supplied
// context.
func (c *Client) SealStatusContext(ctx context.Context) (*SealStatusResult, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("vault client is nil")
	}

	status, err := c.client.Sys().SealStatusWithContext(ctx)
	if err != nil {
		return nil, classifyAdminError(err, "seal status")
	}

	return &SealStatusResult{
		Sealed:             status.Sealed,
		TotalShares:        status.N,
		Threshold:          status.T,
		Progress:           status.Progress,
		Initialized:        status.Initialized,
		ClusterName:        status.ClusterName,
		ClusterID:          status.ClusterID,
		RecoverySeal:       status.RecoverySeal,
		StorageType:        status.StorageType,
		HCPLinkStatus:      status.HCPLinkStatus,
		HCPLinkResourceID:  status.HCPLinkResourceID,
	}, nil
}

// GetSealStatus is a convenience one-shot helper for callers that do not
// need a reusable client.
func GetSealStatus(cfg AdminConfig) (*SealStatusResult, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return client.SealStatus()
}
