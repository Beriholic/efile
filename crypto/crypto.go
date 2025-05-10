package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var (
	IsQuiet bool = false
)

func processKey(key []byte) []byte {
	if len(key) < 16 {
		padded := make([]byte, 16)
		copy(padded, key)
		return padded
	} else if len(key) > 32 {
		return key[:32]
	}
	return key
}

func EncryptName(path string, key []byte) error {
	path = strings.TrimRight(path, "/\\")

	fileInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to get file info: %v", err)
	}

	dir := filepath.Dir(path)
	origName := fileInfo.Name()

	if strings.HasSuffix(origName, ".enc") || strings.HasSuffix(origName, "-enc") {
		if !IsQuiet {
			fmt.Printf("Skipping already encrypted name: %s\n", origName)
		}
		return nil
	}

	encryptedName, err := encryptString(origName, key)
	if err != nil {
		return fmt.Errorf("failed to encrypt name: %v", err)
	}

	suffix := ".enc"
	if fileInfo.IsDir() {
		suffix = "-enc"
	}

	newPath := filepath.Join(dir, encryptedName+suffix)

	err = os.Rename(path, newPath)
	if err != nil {
		return fmt.Errorf("failed to rename: %v", err)
	}

	if !IsQuiet {
		fmt.Printf("Encrypted: %s -> %s\n", origName, filepath.Base(newPath))
	}

	if fileInfo.IsDir() {
		entries, err := os.ReadDir(newPath)
		if err != nil {
			return fmt.Errorf("failed to read directory: %v", err)
		}

		for _, entry := range entries {
			subPath := filepath.Join(newPath, entry.Name())
			err := EncryptName(subPath, key)
			if err != nil {
				return fmt.Errorf("failed to encrypt %s: %v", subPath, err)
			}
		}
	}

	return nil
}

func DecryptName(path string, key []byte) error {
	path = strings.TrimRight(path, "/\\")

	fileInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to get file info: %v", err)
	}

	dir := filepath.Dir(path)
	encName := fileInfo.Name()

	isEncrypted := false
	var encNameWithoutSuffix string

	if strings.HasSuffix(encName, ".enc") {
		isEncrypted = true
		encNameWithoutSuffix = strings.TrimSuffix(encName, ".enc")
	} else if strings.HasSuffix(encName, "-enc") {
		isEncrypted = true
		encNameWithoutSuffix = strings.TrimSuffix(encName, "-enc")
	}

	if !isEncrypted {
		if !IsQuiet {
			fmt.Printf("Skipping non-encrypted name: %s\n", encName)
		}
		return nil
	}

	decryptedName, err := decryptString(encNameWithoutSuffix, key)
	if err != nil {
		return fmt.Errorf("failed to decrypt name: %v", err)
	}

	newPath := filepath.Join(dir, decryptedName)

	err = os.Rename(path, newPath)
	if err != nil {
		return fmt.Errorf("failed to rename: %v", err)
	}

	if !IsQuiet {
		fmt.Printf("Decrypted: %s -> %s\n", encName, decryptedName)
	}

	if fileInfo.IsDir() {
		entries, err := os.ReadDir(newPath)
		if err != nil {
			return fmt.Errorf("failed to read directory: %v", err)
		}

		for _, entry := range entries {
			subPath := filepath.Join(newPath, entry.Name())
			err := DecryptName(subPath, key)
			if err != nil {
				return fmt.Errorf("failed to decrypt %s: %v", subPath, err)
			}
		}
	}

	return nil
}

func encryptString(text string, key []byte) (string, error) {
	keyBytes := processKey(key)

	block, err := aes.NewCipher(keyBytes)
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

	ciphertext := gcm.Seal(nonce, nonce, []byte(text), nil)

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func decryptString(encryptedText string, key []byte) (string, error) {
	ciphertext, err := base64.URLEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	keyBytes := processKey(key)

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func EncryptFileContent(srcPath, dstPath string, key []byte) error {
	keyBytes := processKey(key)

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	plaintext, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to read source file: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	err = os.WriteFile(dstPath, ciphertext, 0644)
	if err != nil {
		return fmt.Errorf("failed to write encrypted file: %v", err)
	}

	return nil
}

func DecryptFileContent(srcPath, dstPath string, key []byte) error {
	keyBytes := processKey(key)

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	ciphertext, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to read encrypted file: %v", err)
	}

	if len(ciphertext) < gcm.NonceSize() {
		return fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt file: %v", err)
	}

	err = os.WriteFile(dstPath, plaintext, 0644)
	if err != nil {
		return fmt.Errorf("failed to write decrypted file: %v", err)
	}

	return nil
}
