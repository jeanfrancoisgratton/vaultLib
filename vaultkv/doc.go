// Package vaultkv provides a lightweight HashiCorp Vault KV v2 client.
//
// It is intentionally focused on the read path first, mirroring the current
// behavior of vaultreader while removing CLI/global-state assumptions so the
// code can be embedded in other tools.
package vaultkv
