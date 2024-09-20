package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "efile",
	Short: "Encrypt and decrypt files",
	Long:  `efile is a CLI tool to encrypt and decrypt files.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Hello efile")
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		fmt.Println("efile error: ", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(encryptCmd)
	rootCmd.AddCommand(decryptCmd)
	rootCmd.AddCommand(versionCmd)
}
