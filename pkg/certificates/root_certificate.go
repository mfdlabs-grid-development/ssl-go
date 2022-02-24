package certificates

import (
	"fmt"

	"git.mfdlabs.local/petko/mfdlabs-ssl-go/pkg/configuration"
	"git.mfdlabs.local/petko/mfdlabs-ssl-go/pkg/helper"
)

func LoadRootCertificates(configFilePath string, conf *configuration.SslConfiguration, loadedRootCerts map[string]*configuration.RootCertificateAuthority) {
	// check if the root certificates are empty
	if len(conf.RootCertificateAuthorities) != 0 {
		// load the root certificates
		for _, rootCert := range conf.RootCertificateAuthorities {
			loadRootCertificateAuthority(configFilePath, rootCert, loadedRootCerts)
		}
	}
}

func loadRootCertificateAuthority(configFilePath string, rootCert *configuration.RootCertificateAuthority, loadedRootCerts map[string]*configuration.RootCertificateAuthority) {
	err := DetermineIfRootCAIsReference(configFilePath, rootCert)

	rootCaName := helper.ReplaceEnvironmentExpression(rootCert.RootCertificateName)
	rootCaPassword := helper.ReplaceEnvironmentExpression(rootCert.RootCertificatePassword)
	rootCaPfxPassword := helper.ReplaceEnvironmentExpression(rootCert.RootCertificatePfxPassword)

	// check if the root certificate is already loaded
	if _, ok := loadedRootCerts[rootCaName]; ok {
		return
	}

	fmt.Printf("Loading root certificate authority: %s\n", rootCaName)

	if err != nil {
		panic(err)
	}

	// Check if the required fields are empty
	if rootCaName == "" {
		panic("The root certificate authority name is empty")
	}

	if rootCaPassword == "" {
		panic("The root certificate authority password is empty")
	}

	if rootCaPfxPassword == "" {
		panic("The root certificate authority pfx password is empty")
	}

	// Check if password is less than 8 characters
	if len(rootCaPassword) < 8 {
		panic("The root certificate authority password is less than 8 characters")
	}

	// Check if password is less than 8 characters
	if len(rootCaPfxPassword) < 8 {
		panic("The root certificate authority pfx password is less than 8 characters")
	}

	// Get string of if the cert should be inserted into the trust store
	shouldInsertIntoTrustedStore := helper.Ternary(rootCert.ShouldInsertIntoTrustedStore, "YES", "NO").(string)
	skipDhParam := helper.Ternary(rootCert.GenerateDHParameters, "NO", "YES").(string)
	hasExtensionFile := helper.Ternary(rootCert.HasExtensionFile, "YES", "NO").(string)

	configuration.GenerateRootCertificateConfigurationFileIfNotExists(rootCert)

	// Get command text
	command := fmt.Sprintf("./ssl/generate-root-ca.sh %s %s %s %s %s %s", rootCaName, rootCaPassword, rootCaPfxPassword, shouldInsertIntoTrustedStore, skipDhParam, hasExtensionFile)

	// Execute the command
	helper.ExecuteRawCommand(command)

	// Add the root certificate to the map
	loadedRootCerts[rootCaName] = rootCert
}
