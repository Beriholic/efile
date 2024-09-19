package cmd

import (
	"fmt"
	"os"

	"github.com/Beriholic/efile/hash"
	"github.com/Beriholic/efile/state"
	"github.com/spf13/cobra"
)

var encryptCmd = &cobra.Command{
	Use:   "enc [path] [key]",
	Short: "Encrypt a file or folder",
	Long:  `Encrypt a file or folder.`,
	Run: func(cmd *cobra.Command, args []string) {
		state.IsQuiet, _ = cmd.Flags().GetBool("quiet")

		if len(args) < 2 {
			fmt.Println("Please provide a path and a key")
			return
		}

		key := make([]byte, 32)
		copy(key, args[len(args)-1])

		for i := 0; i < len(args)-1; i++ {
			path := args[i]
			info, err := os.Stat(path)
			if err != nil {
				fmt.Println("Error: ", err)
				return
			}

			if info.IsDir() {
				err = hash.ProcessFolder(path, key)
			} else {
				err = hash.EncryptAndSave(path, key)
			}
			if err != nil {
				fmt.Println("Encryption error: ", err)
				return
			}
		}
	},
}

func init() {
	encryptCmd.Flags().BoolP("quiet", "q", false, "suppress output")
}
