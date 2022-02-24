package pkg

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"git.mfdlabs.local/petko/mfdlabs-ssl-go/pkg/configuration"
	"gopkg.in/yaml.v2"
)

// Function to Load the configuration file
func LoadConfiguration(configurationFilePath string) (*configuration.SslConfiguration, error) {
	// Check if the configuration file exists
	fileInfo, err := os.Stat(configurationFilePath)

	if os.IsNotExist(err) {
		return &configuration.SslConfiguration{}, err
	}

	// Check if the configuration file is a directory
	if fileInfo.IsDir() {
		return &configuration.SslConfiguration{}, fmt.Errorf("the configuration file path is a directory")
	}

	// Get the file extension
	fileExtension := fileInfo.Name()[len(fileInfo.Name())-3:]

	// Determine if the file extension is json or yaml
	if fileExtension == "yml" || fileExtension == "yaml" {
		return loadConfigurationYaml(configurationFilePath)
	}

	if fileExtension == "json" {
		return loadConfigurationJson(configurationFilePath)
	}

	return &configuration.SslConfiguration{}, fmt.Errorf("the configuration file extension is not supported")
}

func loadConfigurationJson(configurationFilePath string) (*configuration.SslConfiguration, error) {
	// Read the configuration file content

	content, err := ioutil.ReadFile(configurationFilePath)

	if err != nil {
		return &configuration.SslConfiguration{}, err
	}

	// Unmarshal the configuration file content
	var configOut configuration.SslConfiguration

	err = json.Unmarshal(content, &configOut)

	if err != nil {
		return &configuration.SslConfiguration{}, err
	}

	return &configOut, nil
}

func loadConfigurationYaml(configurationFilePath string) (*configuration.SslConfiguration, error) {
	// Read the configuration file content

	content, err := ioutil.ReadFile(configurationFilePath)

	if err != nil {
		return &configuration.SslConfiguration{}, err
	}

	// Unmarshal the configuration file content
	var configOut configuration.SslConfiguration

	err = yaml.Unmarshal(content, &configOut)

	if err != nil {
		return &configuration.SslConfiguration{}, err
	}

	return &configOut, nil
}
