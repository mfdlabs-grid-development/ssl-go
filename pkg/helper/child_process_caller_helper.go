package helper

import (
	"fmt"
	"os"
	"os/exec"
)

// A function that executes a raw command and will panic if the command fails
func ExecuteRawCommand(command string) {
	// Execute the command
	err := ExecuteCommand(command)

	// Check if the command failed
	if err != nil {
		panic(fmt.Errorf("failed to execute the command: %s, because: %s", command, err))
	}
}

func ExecuteCommand(command string) error {
	// Execute the command
	cmd := exec.Command("/bin/sh", "-c", command)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Execute the command
	return cmd.Run()
}
