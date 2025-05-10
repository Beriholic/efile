package cmd

import (
	"fmt"
	"os"
	"syscall"

	"github.com/Beriholic/efile/crypto"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var decryptCmd = &cobra.Command{
	Use:   "dec [path]",
	Short: "Decrypt a file or folder name",
	Long:  `Decrypt both the name and content of a file or folder. If a folder is specified, all files and subfolders within it will also be decrypted.`,
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

		fmt.Println()

		fileInfo, err := os.Stat(path)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		if !fileInfo.IsDir() {
			tempPath := path + ".tmp"

			err = crypto.DecryptFileContent(path, tempPath, key)
			if err != nil {
				fmt.Printf("Error decrypting file content: %v\n", err)
				os.Remove(tempPath) // 清理临时文件
				return
			}

			err = os.Rename(tempPath, path)
			if err != nil {
				fmt.Printf("Error replacing original file: %v\n", err)
				return
			}

			if !crypto.IsQuiet {
				fmt.Printf("File content decrypted: %s\n", path)
			}
		}

		err = crypto.DecryptName(path, key)
		if err != nil {
			fmt.Printf("Error decrypting name %s: %v\n", path, err)
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
