package cmd

import (
	"fmt"
	"os"
	"syscall"

	"github.com/Beriholic/efile/crypto"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var encryptCmd = &cobra.Command{
	Use:   "enc [path]",
	Short: "Encrypt a file or folder name",
	Long:  `Encrypt both the name and content of a file or folder. If a folder is specified, all files and subfolders within it will also be encrypted.`,
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

		fmt.Println()

		if string(key) != string(confirmKey) {
			fmt.Println("Error: keys do not match")
			return
		}

		fileInfo, err := os.Stat(path)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		if !fileInfo.IsDir() {
			tempPath := path + ".tmp"

			err = crypto.EncryptFileContent(path, tempPath, key)
			if err != nil {
				fmt.Printf("Error encrypting file content: %v\n", err)
				os.Remove(tempPath) // 清理临时文件
				return
			}

			err = os.Rename(tempPath, path)
			if err != nil {
				fmt.Printf("Error replacing original file: %v\n", err)
				return
			}

			if !crypto.IsQuiet {
				fmt.Printf("File content encrypted: %s\n", path)
			}
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
