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

	fmt.Printf("Loading root certificate: %s\n", rootCaName)

	if err != nil {
		panic(err)
	}

	// Check if the required fields are empty
	if rootCaName == "" {
		panic("The root certificate name cannot be empty")
	}

	if rootCaPassword == "" {
		panic("The root certificate password cannot be empty")
	}

	if rootCaPfxPassword == "" {
		panic("The root certificate PFX password cannot be empty")
	}

	// Check if password is less than 8 characters
	if len(rootCaPassword) < 4 {
		panic("The root certificate password cannot be less than 4 characters")
	}

	// Check if password is less than 8 characters
	if len(rootCaPfxPassword) < 4 {
		panic("The root certificate PFX password cannot be less than 4 characters")
	}

	err = helper.CheckCertificateName(rootCaName)
	if err != nil {
		panic(err)
	}

	// Get string of if the cert should be inserted into the trust store
	shouldInsertIntoTrustedStore := helper.Ternary(rootCert.ShouldInsertIntoTrustedStore, "YES", "NO").(string)
	skipDhParam := helper.Ternary(rootCert.GenerateDHParameters, "NO", "YES").(string)

	keyLength := rootCert.PrivateKeySize

	// If the key length is not set, set it to 2048
	if keyLength == 0 {
		keyLength = 2048
	}

	// If the key length is not 1024, 2048 or 4096, error out
	if keyLength != 1024 && keyLength != 2048 && keyLength != 4096 {
		panic("The key length must be 1024, 2048 or 4096")
	}

	expirationInDays := rootCert.ValidityPeriod

	// If the expiration in days is not set, set it to 4086
	if expirationInDays == 0 {
		expirationInDays = 4086
	}

	// If the expiration in days is less than 0, error out
	if expirationInDays < 0 {
		panic("The expiration in days must be greater than or equal to 0")
	}

	configuration.GenerateRootCertificateConfigurationFileIfNotExists(rootCert)

	rootCaPasswordFilename, err := helper.WritePasswordFile("root", rootCaName, "normal", rootCaPassword)
	if err != nil {
		panic(err)
	}
	rootCaPfxPasswordFilename, err := helper.WritePasswordFile("root", rootCaName, "pfx", rootCaPfxPassword)
	if err != nil {
		panic(err)
	}

	// Get command text
	command := fmt.Sprintf("./ssl/generate-root-ca.sh %s @%s @%s %s %s YES %d %d", rootCaName, rootCaPasswordFilename, rootCaPfxPasswordFilename, shouldInsertIntoTrustedStore, skipDhParam, expirationInDays, keyLength)

	// Execute the command
	helper.ExecuteRawCommand(command)

	// Add the root certificate to the map
	loadedRootCerts[rootCaName] = rootCert

	defer helper.DeleteTmpPasswords([]string{rootCaPasswordFilename, rootCaPfxPasswordFilename})
}
