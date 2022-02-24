package certificates

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"git.mfdlabs.local/petko/mfdlabs-ssl-go/pkg/configuration"
	"gopkg.in/yaml.v2"
)

func reloadCertJson(path string, outCer interface{}) error {
	// Read the configuration file content
	content, err := ioutil.ReadFile(path)

	if err != nil {
		return err
	}

	err = json.Unmarshal(content, outCer)

	if err != nil {
		return err
	}

	return nil
}

func reloadCertYaml(path string, outCer interface{}) error {
	// Read the configuration file content
	content, err := ioutil.ReadFile(path)

	if err != nil {
		return err
	}

	err = yaml.Unmarshal(content, outCer)

	if err != nil {
		return err
	}

	return nil
}

func checkExtensionAndReload(certificate interface{}, path string) error {
	// Check if the file does not exist
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("the referenced configuration file does not exist: %s", path)
	}

	fileInfo, _ := os.Stat(path)

	if fileInfo.IsDir() {
		return fmt.Errorf("the referenced configuration file %s is a directory", path)
	}

	// Get the file extension
	fileExtension := fileInfo.Name()[len(fileInfo.Name())-3:]

	// Determine if the file extension is json or yaml
	if fileExtension == "yml" || fileExtension == "yaml" {
		return reloadCertYaml(path, certificate)
	}

	if fileExtension == "json" {
		return reloadCertJson(path, certificate)
	}

	return fmt.Errorf("the referenced configuration file extension is not supported")
}

func DetermineIfLeafCertificateIsReference(configurationFilePath string, certificate *configuration.LeafCertificate) error {
	isRefCert := certificate.ReferencedConfigurationPath != ""

	// We need to load the referenced configuration file
	if isRefCert {
		// Determine if the referenced path is absolute or relative
		if isAbsolutePath(certificate.ReferencedConfigurationPath) {
			return checkExtensionAndReload(&certificate, certificate.ReferencedConfigurationPath)
		}

		// The referenced path is relative, transform it to absolute to the path of the configuration file
		// If the referenced path starts with ./ remove it, ../ is ok
		certPath := certificate.ReferencedConfigurationPath

		if certPath[0:2] == "./" {
			certPath = certPath[2:]
		}

		// get config path without file name
		configFilePath := configurationFilePath[:len(configurationFilePath)-len(filepath.Base(configurationFilePath))]

		absolutePath := configFilePath + certPath

		return checkExtensionAndReload(&certificate, absolutePath)
	}

	return nil
}

func DetermineIfRootCAIsReference(configurationFilePath string, certificate *configuration.RootCertificateAuthority) error {
	isRefCert := certificate.ReferencedConfigurationPath != ""

	// We need to load the referenced configuration file
	if isRefCert {
		// Determine if the referenced path is absolute or relative
		if isAbsolutePath(certificate.ReferencedConfigurationPath) {
			return checkExtensionAndReload(&certificate, certificate.ReferencedConfigurationPath)
		}

		// The referenced path is relative, transform it to absolute to the path of the configuration file
		// If the referenced path starts with ./ remove it, ../ is ok
		certPath := certificate.ReferencedConfigurationPath

		if certPath[0:2] == "./" {
			certPath = certPath[2:]
		}

		// get config path without file name
		configFilePath := configurationFilePath[:len(configurationFilePath)-len(filepath.Base(configurationFilePath))]

		absolutePath := configFilePath + certPath

		return checkExtensionAndReload(&certificate, absolutePath)
	}

	return nil
}

func DetermineIfIntermediateCAIsReference(configurationFilePath string, certificate *configuration.IntermediateCertificateAuthority) error {
	isRefCert := certificate.ReferencedConfigurationPath != ""

	// We need to load the referenced configuration file
	if isRefCert {
		// Determine if the referenced path is absolute or relative
		if isAbsolutePath(certificate.ReferencedConfigurationPath) {
			return checkExtensionAndReload(&certificate, certificate.ReferencedConfigurationPath)
		}

		// The referenced path is relative, transform it to absolute to the path of the configuration file
		// If the referenced path starts with ./ remove it, ../ is ok
		certPath := certificate.ReferencedConfigurationPath

		if certPath[0:2] == "./" {
			certPath = certPath[2:]
		}

		// get config path without file name
		configFilePath := configurationFilePath[:len(configurationFilePath)-len(filepath.Base(configurationFilePath))]

		absolutePath := configFilePath + certPath

		return checkExtensionAndReload(&certificate, absolutePath)
	}

	return nil
}

func isAbsolutePath(path string) bool {
	return path[0] == '/'
}
