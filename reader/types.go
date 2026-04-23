// vaultLib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: reader/types.go
// Original timestamp: 2026/04/23 14:34:48

package reader

import (
	"github.com/hashicorp/vault/api"
	"vaultreader/shared"
)

type ReadOptions struct {
	Version int    `json:"version"`
	Field   string `json:"field"`
}

type Secret struct {
	MountPath        string                 `json:"mountPath"`
	Path             string                 `json:"path"`
	RequestedVersion int                    `json:"requestedVersion,omitempty"`
	Version          int                    `json:"version,omitempty"`
	Data             map[string]interface{} `json:"data"`
}

type Client struct {
	cfg    shared.Config
	client *api.Client
}
