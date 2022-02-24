package helper

import (
	"fmt"
	"os"
	"strings"
)

// There's a special kind of var here that does like this:
// ${{ env.VAR_NAME }}, which is a special kind of var that will be replaced with the value of the environment variable VAR_NAME.
// This is useful when you want to pass the value of an environment variable to a command.
// We have to parse this out, and replace it with the value of the environment variable.
func ReplaceEnvironmentExpression(input string) string {
	// Check if the input is empty
	if input == "" {
		return input
	}

	// Check if the input contains the special var
	if !strings.Contains(input, "${{ ") {
		return input
	}

	// Split the input into parts
	parts := strings.Split(input, "${{ ")

	// We now need to get the part in the middle of ${{ }}
	otherPart := parts[1]

	// Split the middle part into parts
	middleParts := strings.Split(otherPart, " }}")

	// Get the name of the environment variable
	middlePart := middleParts[0]

	// Check if the middle part starts with env.
	if !strings.HasPrefix(middlePart, "env.") {
		return input
	}

	// Get the env var name
	envVarName := middlePart[4:]

	// Check if the env var name is empty
	if envVarName == "" {
		return input
	}

	// Get the env var value
	envVarValue := os.Getenv(envVarName)

	// Check if the env var value is empty, if so, return it but warn the user
	if envVarValue == "" {
		fmt.Printf("WARNING: The environment variable %s is empty, the value will be replaced with an empty string\n", envVarName)
	}

	// Replace the env var value with the env var name
	return envVarValue
}
