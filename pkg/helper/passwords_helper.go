package helper

import (
	"fmt"
	"os"
)

func WritePasswordFile(certType string, certName string, passwordType string, password string) (string, error) {
	// Get cwd
	cwd, err := os.Getwd()

	if err != nil {
		return "", err
	}

	// Check if the cwd is empty
	if cwd == "" {
		return "", fmt.Errorf("failed to get the current working directory")
	}

	fileName := fmt.Sprintf("%s/bin/%s_%s_%s.txt", cwd, certType, certName, passwordType)
	file, err := os.Create(fileName)

	if err != nil {
		return "", err
	}

	defer file.Close()

	_, err = file.WriteString(password)

	if err != nil {
		return "", err
	}

	return fileName, nil
}

func DeleteTmpPasswords(fileNames []string) {
	for _, fileName := range fileNames {
		os.Remove(fileName)
	}
}
