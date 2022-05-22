package ssl

import (
	"errors"
	"os"
	"os/exec"
)

func tryCloneRepo() error {
	// determine if we have git installed
	if _, err := exec.LookPath("git"); err != nil {
		return err
	}

	// determine if the repo is already cloned
	if _, err := os.Stat("./ssl/generate-root-ca.sh"); errors.Is(err, os.ErrNotExist) {
		// clone the repo
		err := exec.Command("git", "clone", "https://github.com/mfdlabs/ssl", "./ssl").Run()

		return err
	}

	return nil
}

// We have 3 scripts:
// - generate-root-ca.sh
// - generate-intermediate-ca.sh
// - generate-certificates-v2.sh
func DetermineIfScriptsAvailable() error {
	return tryCloneRepo()
}
