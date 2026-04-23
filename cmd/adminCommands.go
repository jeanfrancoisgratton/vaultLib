// vaultreader
// Written by J.F. Gratton <jean-francois@famillegratton.net>
// Original timestamp: 2025/09/18 13:48
// Original filename: src/cmd/adminCommands.go

package cmd

import (
	"fmt"
	"vaultreader/admin"

	"github.com/spf13/cobra"
)

var adminCmd = &cobra.Command{
	Use:   "conf",
	Short: "Configuration (SHOW ALL / ALTER SYSTEM) helpers",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Valid subcommands are: { list | get | set }")
	},
}

func unsealCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "unseal",
		Short:  "Unseal Vault",
		Hidden: true, // <- hides from help/usage and shell completion, but still runnable
		RunE: func(cmd *cobra.Command, args []string) error {
			admin.UnsealVault()
			return nil
		},
	}
	return cmd
}

func init() {
	//adminCmd.AddCommand(unsealCmd)
}
