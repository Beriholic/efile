package cmd

import (
	"fmt"
	"os"
	"sync"

	"github.com/Beriholic/efile/hash"
	"github.com/Beriholic/efile/state"
	"github.com/spf13/cobra"
)

var encryptCmd = &cobra.Command{
	Use:   "enc [path]",
	Short: "Encrypt a file or folder",
	Long:  `Encrypt a file or folder.`,
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

				if !info.IsDir() && !info.Mode().IsRegular() {
					fmt.Println("Error: ", path, " is not a file or folder")
					return
				}

				if info.IsDir() {
					err = hash.ProcessFolder(path, key)
					if err != nil {
						errors <- err
					}
				} else {
					err = hash.EncryptAndSave(path, key)
					if err != nil {
						errors <- err
					}
				}
			}(args[i])
		}

		wg.Wait()
		close(errors)

		if len(errors) > 0 {
			fmt.Println("Encryption errors, please check your key and try again, do you want to check them out? [y/n]")
			response := ""
			fmt.Scanf("%s", &response)
			if response != "y" {
				return
			}

			for err := range errors {
				fmt.Println("Encryption error: ", err)
			}
			return
		}

		fmt.Println("All done no error")
	},
}

func init() {
	encryptCmd.Flags().BoolP("quiet", "q", false, "suppress output")
}
