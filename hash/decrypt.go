package hash

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/Beriholic/efile/state"
)

func decryptFile(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func decryptFileName(encryptedFileName string, key []byte) (string, error) {
	encryptedData, err := base64.URLEncoding.DecodeString(encryptedFileName)
	if err != nil {
		return "", err
	}

	decryptedData, err := decryptFile(encryptedData, key)
	if err != nil {
		return "", err
	}

	return string(decryptedData), nil
}

func ProcessFolderDecrypt(folder string, key []byte) error {
	var wg sync.WaitGroup
	errors := make(chan error)
	return filepath.Walk(folder, func(path string, info os.FileInfo, err error) error {
		if len(errors) == 0 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err != nil {
					errors <- err
				}
				if !info.IsDir() {
					err = DecryptAndSave(path, key)
					if err != nil {
						errors <- err
					}
				}
			}()
		}
		wg.Wait()
		if len(errors) > 0 {
			return <-errors
		}
		return nil
	})
}

func DecryptAndSave(filePath string, key []byte) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	decryptedData, err := decryptFile(data, key)
	if err != nil {
		return err
	}

	encryptedFileName := filepath.Base(filePath[:len(filePath)-len(filepath.Ext(filePath))])
	decryptedFileName, err := decryptFileName(encryptedFileName, key)
	if err != nil {
		return err
	}

	decryptedFilePath := filepath.Join(filepath.Dir(filePath), decryptedFileName)
	err = os.WriteFile(decryptedFilePath, decryptedData, 0644)
	if err != nil {
		return err
	}

	err = os.Remove(filePath)
	if err != nil {
		return err
	}

	if !state.IsQuiet {
		fmt.Println("File decrypt success: ", filePath, " -> ", decryptedFilePath)
	}

	return nil
}
