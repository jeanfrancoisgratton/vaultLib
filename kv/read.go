// vaultreader
// Written by J.F. Gratton <jean-francois@famillegratton.net>
// Original timestamp : 2025/05/31 22:43
// Refactored to consume the reusable vaultkv package.

package kv

import (
	"fmt"
	"vaultreader/types"
	"vaultreader/vaultkv"

	ce "github.com/jeanfrancoisgratton/customError/v3"
	hfl "github.com/jeanfrancoisgratton/helperFunctions/v3/logging"
	hftx "github.com/jeanfrancoisgratton/helperFunctions/v3/terminalfx"
)

// ReadSecrets reads a secret from the Vault secret path through the reusable
// vaultkv package, then formats output for the CLI.
func ReadSecrets(path string) *ce.CustomError {
	hfl.Debugf("Starting ReadSecrets for path=%s", path)

	cfg := vaultkv.Config{
		Address:   types.VaultServerAddress,
		Token:     types.VaultAuthToken,
		MountPath: types.KVEngineMountPath,
	}

	secret, err := vaultkv.ReadSecret(cfg, path, vaultkv.ReadOptions{
		Version: types.KVSecretVersion,
		Field:   types.KVSecretField,
	})
	if err != nil {
		if !types.Quiet {
			fmt.Println(hftx.FatalSkullBonesGlyph(err.Error()))
		}
		hfl.Errorf(err.Error())
		return &ce.CustomError{Title: err.Title, Message: err.Message, Code: err.Code}
	}

	return outputData(secret.Data, types.Quiet)
}
