package cmd

import (
	"fmt"
	"syscall"

	"github.com/Beriholic/efile/crypto"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var decryptCmd = &cobra.Command{
	Use:   "dec [path]",
	Short: "Decrypt a file or folder name",
	Long:  `Decrypt the name of a file or folder. If a folder is specified, all files and subfolders within it will also be decrypted.`,
	Run: func(cmd *cobra.Command, args []string) {
		crypto.IsQuiet, _ = cmd.Flags().GetBool("quiet")

		if len(args) == 0 {
			fmt.Println("Please provide a path")
			return
		}

		path := args[0]

		fmt.Print("Enter decryption key: ")
		key, err := term.ReadPassword(int(syscall.Stdin))

		if err != nil {
			fmt.Printf("Error reading key: %v\n", err)
			return
		}

		err = crypto.DecryptName(path, key)
		if err != nil {
			fmt.Printf("Error decrypting %s: %v\n", path, err)
			return
		}

		if !crypto.IsQuiet {
			fmt.Println("Decryption completed successfully.")
		}
	},
}

func init() {
	decryptCmd.Flags().BoolP("quiet", "q", false, "suppress output")
}
