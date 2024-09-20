package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionNumber = "0.2.0"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of efile",
	Long:  `Print the version number of efile.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("efile version %s\n", versionNumber)
	},
}
