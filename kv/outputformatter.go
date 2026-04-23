// vaultreader
// Written by J.F. Gratton <jean-francois@famillegratton.net>
// Original timestamp : 2025/06/04 14:55
// Original filename : src/kv/outputformatter.go

package kv

import (
	"encoding/json"
	"fmt"
	"os"
	"vaultreader/types"

	ce "github.com/jeanfrancoisgratton/customError/v3"
	hfl "github.com/jeanfrancoisgratton/helperFunctions/v3/logging"
	hftx "github.com/jeanfrancoisgratton/helperFunctions/v3/terminalfx"
)

func outputData(data map[string]interface{}, suppress bool) *ce.CustomError {
	if types.KVSecretField != "" {
		hfl.Debugf("Reading field: %s", types.KVSecretField)
		val, found := data[types.KVSecretField]
		if !found {
			title := "ReadSecret error"
			message := fmt.Sprintf("Field %s not found", types.KVSecretField)
			code := types.ErrFieldNotFound
			if !types.Quiet {
				fmt.Println(hftx.FatalSkullBonesGlyph(title + " " + message))
			}
			cerr := ce.CustomError{Title: title, Message: message, Code: code}
			hfl.Errorf(cerr.ErrorNoColor())
			return &cerr
		}
		if suppress {
			return nil
		}
		if types.OutputFormat == "json" {
			out := map[string]interface{}{types.KVSecretField: val}
			json.NewEncoder(os.Stdout).Encode(out)
		} else {
			fmt.Printf("%v\n", val)
		}
		return nil
	}

	if suppress {
		return nil
	}

	if types.OutputFormat == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(data); err != nil {
			title := "JSON encoding error"
			message := err.Error()
			code := types.ErrExtractData
			if !types.Quiet {
				fmt.Println(hftx.FatalSkullBonesGlyph(title + " " + message))
			}
			cerr := ce.CustomError{Title: title, Message: message, Code: code}
			hfl.Errorf(cerr.ErrorNoColor())
			return &cerr
		}
	} else {
		for k, v := range data {
			fmt.Printf("%s: %v\n", k, v)
		}
	}
	return nil
}
