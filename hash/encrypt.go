package hash

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/Beriholic/efile/state"
)

func encryptFile(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	cipherText := gcm.Seal(nonce, nonce, data, nil)
	return cipherText, nil
}

func encryptFileName(fileName string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	cipherText := gcm.Seal(nonce, nonce, []byte(fileName), nil)
	return base64.URLEncoding.EncodeToString(cipherText), nil
}

func ProcessFolder(folderPath string, key []byte) error {
	var wg sync.WaitGroup
	errors := make(chan error, 1)

	err := filepath.Walk(folderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err != nil {
				errors <- err
			}
			if !info.IsDir() {
				err = EncryptAndSave(path, key)
				if err != nil {
					errors <- err
				}
			}
		}()
		return nil
	})
	if err != nil {
		return err
	}
	go func() {
		wg.Wait()
		close(errors)
	}()

	for err := range errors {
		if err != nil {
			return err
		}
	}

	return nil
}

func EncryptAndSave(filePath string, key []byte) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	encryptedData, err := encryptFile(data, key)
	if err != nil {
		return err
	}

	encryptedFileName, err := encryptFileName(filepath.Base(filePath), key)
	if err != nil {
		return err
	}

	encryptedFilePath := filepath.Join(filepath.Dir(filePath), encryptedFileName)
	err = os.WriteFile(encryptedFilePath, encryptedData, 0644)
	if err != nil {
		return err
	}

	if !state.IsQuiet {
		fmt.Printf("File encrypt success : %s -> %s\n", filePath, encryptedFilePath)
	}

	err = os.Remove(filePath)
	if err != nil {
		return err
	}

	return nil
}
