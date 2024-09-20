package cmd

import (
	"fmt"
	"os"
	"sync"

	"github.com/Beriholic/efile/hash"
	"github.com/Beriholic/efile/state"
	"github.com/spf13/cobra"
)

var decryptCmd = &cobra.Command{
	Use:   "dec [path]",
	Short: "Decrypt a file or folder",
	Long:  `Decrypt a file or folder.`,
	Run: func(cmd *cobra.Command, args []string) {
		state.IsQuiet, _ = cmd.Flags().GetBool("quiet")

		if len(args) == 0 {
			fmt.Println("Please provide a path")
			return
		}

		fmt.Print("Enter key: ")
		_key := ""
		fmt.Scanf("%s", &_key)

		key := make([]byte, 32)
		copy(key, _key)

		var wg sync.WaitGroup
		errors := make(chan error, len(args))

		for i := 0; i < len(args); i++ {
			wg.Add(1)
			go func(path string) {
				defer wg.Done()

				info, err := os.Stat(path)
				if err != nil {
					fmt.Println("Error: ", err)
					return
				}

				if info.IsDir() {
					err = hash.ProcessFolderDecrypt(path, key)
					if err != nil {
						errors <- err
					}
				} else {
					err = hash.DecryptAndSave(path, key)
					if err != nil {
						errors <- err
					}
				}
			}(args[i])
		}

		wg.Wait()

		if len(errors) > 0 {
			fmt.Println("Decryption errors, Do you want to check them out? [y/n]")
			response := ""
			fmt.Scanf("%s", &response)
			if response != "y" {
				return
			}

			for err := range errors {
				fmt.Println("Decryption error: ", err)
			}
			return
		}
		fmt.Println("All done no error")
	},
}

func init() {
	decryptCmd.Flags().BoolP("quiet", "q", false, "suppress output")
}
