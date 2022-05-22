package helper

import (
	"fmt"
	"regexp"
)

func CheckCertificateName(certName string) error {
	if certName == "" {
		return fmt.Errorf("certificate name cannot be empty")
	}

	// The certificate name has to match the following regex:
	// ^[a-zA-Z0-9-_]{1,64}$
	if !regexp.MustCompile(`^[a-zA-Z0-9-_]{1,64}$`).MatchString(certName) {
		return fmt.Errorf("certificate name has to match the following regex: ^[a-zA-Z0-9-_]{1,64}$")
	}

	return nil
}
