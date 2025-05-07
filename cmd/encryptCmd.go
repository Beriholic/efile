package cmd

import (
	"fmt"
	"syscall"

	"github.com/Beriholic/efile/crypto"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var encryptCmd = &cobra.Command{
	Use:   "enc [path]",
	Short: "Encrypt a file or folder name",
	Long:  `Encrypt the name of a file or folder. If a folder is specified, all files and subfolders within it will also be encrypted.`,
	Run: func(cmd *cobra.Command, args []string) {
		crypto.IsQuiet, _ = cmd.Flags().GetBool("quiet")

		if len(args) == 0 {
			fmt.Println("Please provide a path")
			return
		}

		path := args[0]

		fmt.Print("Enter encryption key: ")

		key, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Printf("Error reading key: %v\n", err)
			return
		}

		fmt.Println()

		fmt.Print("Confirm encryption key: ")

		confirmKey, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Printf("Error reading key: %v\n", err)
			return
		}

		if string(key) != string(confirmKey) {
			fmt.Println("Error: keys do not match")
			return
		}

		err = crypto.EncryptName(path, key)
		if err != nil {
			fmt.Printf("Error encrypting %s: %v\n", path, err)
			return
		}

		if !crypto.IsQuiet {
			fmt.Println("Encryption completed successfully.")
		}
	},
}

func init() {
	encryptCmd.Flags().BoolP("quiet", "q", false, "suppress output")
}
