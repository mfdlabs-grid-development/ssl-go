package certificates

import (
	"fmt"

	"git.mfdlabs.local/petko/mfdlabs-ssl-go/pkg/configuration"
	"git.mfdlabs.local/petko/mfdlabs-ssl-go/pkg/helper"
)

func LoadIntermediateCertificates(configFilePath string, conf *configuration.SslConfiguration, loadedIntCerts map[string]*configuration.IntermediateCertificateAuthority) {
	// check if the int ca certificates are empty
	if len(conf.IntermediateCertificateAuthorities) != 0 {
		// load the int ca certificates
		for _, intCert := range conf.IntermediateCertificateAuthorities {
			loadIntermediateCertificateAuthority(configFilePath, intCert, loadedIntCerts, conf.IntermediateCertificateAuthorities)
		}
	}
}

func loadIntermediateCertificateAuthority(configFilePath string, intCert *configuration.IntermediateCertificateAuthority, loadedIntCerts map[string]*configuration.IntermediateCertificateAuthority, intCerts []*configuration.IntermediateCertificateAuthority) {
	err := DetermineIfIntermediateCAIsReference(configFilePath, intCert)

	caChainName := helper.ReplaceEnvironmentExpression(intCert.LastChainCertificateName)
	caChainPassword := helper.ReplaceEnvironmentExpression(intCert.LastChainCertificatePassword)
	intCertName := helper.ReplaceEnvironmentExpression(intCert.IntermediateCertificateAuthorityName)
	intCertPassword := helper.ReplaceEnvironmentExpression(intCert.IntermediateCertificateAuthorityPassword)
	intCertPfxPassword := helper.ReplaceEnvironmentExpression(intCert.IntermediateCertificateAuthorityPfxPassword)

	// check if the root certificate is already loaded
	if _, ok := loadedIntCerts[caChainName]; ok {
		return
	}

	fmt.Printf("Loading intermediate certificate: %s\n", intCertName)

	if err != nil {
		panic(err)
	}

	// Check if the required fields are empty
	if caChainName == "" {
		panic("The ca chain certificate name cannot be empty")
	}

	// Chain cannot be the same as the int cert if it's not a Root CA
	if intCertName == caChainName {
		if !intCert.IsLastChainCertificateRootCertificateAuthority {
			panic("The chain certificate name cannot be the same as the intermediate certificate name if it's not a root certificate authority")
		}
	}

	if caChainPassword == "" {
		panic("The chain certificate password cannot be empty")
	}

	// Check if password is less than 8 characters
	if len(caChainPassword) < 4 {
		panic("The chain certificate password cannot be less than 4 characters")
	}

	if intCertName == "" {
		panic("The intermediate certificate name cannot be empty")
	}

	// Check if password is less than 8 characters
	if len(intCertPassword) < 4 {
		panic("The intermediate certificate password cannot be less than 4 characters")
	}

	// Check if password is less than 8 characters
	if len(intCertPfxPassword) < 4 {
		panic("The intermediate certificate PFX password cannot be less than 4 characters")
	}

	err = helper.CheckCertificateName(caChainName)
	if err != nil {
		panic(err)
	}
	err = helper.CheckCertificateName(intCertName)
	if err != nil {
		panic(err)
	}

	// Section for generating the ca chain certificate if it's in the config and further down in the code
	if len(intCerts) > 0 && !intCert.IsLastChainCertificateRootCertificateAuthority {
		// Check if we have the last chain certificate generated
		if _, ok := loadedIntCerts[caChainName]; !ok {
			// iterate through the int certs until we find the last chain certificate
			for _, intCert := range intCerts {
				if intCert.IntermediateCertificateAuthorityName == caChainName {
					loadIntermediateCertificateAuthority(configFilePath, intCert, loadedIntCerts, intCerts)
				}
			}
		}
	}

	// Get string of if the cert should be inserted into the trust store
	shouldInsertIntoTrustedStore := helper.Ternary(intCert.ShouldInsertIntoTrustedStore, "YES", "NO").(string)
	skipDhParam := helper.Ternary(intCert.GenerateDHParameters, "NO", "YES").(string)
	keepCertificateRequestFile := helper.Ternary(intCert.KeepCertificateRequestFile, "YES", "NO").(string)
	isLastChainRootCa := helper.Ternary(intCert.IsLastChainCertificateRootCertificateAuthority, "YES", "NO").(string)

	keyLength := intCert.PrivateKeySize

	// If the key length is not set, set it to 2048
	if keyLength == 0 {
		keyLength = 2048
	}

	// If the key length is not 1024, 2048 or 4096, error out
	if keyLength != 1024 && keyLength != 2048 && keyLength != 4096 {
		panic("The key length must be 1024, 2048 or 4096")
	}

	expirationInDays := intCert.ValidityPeriod

	// If the expiration in days is not set, set it to 4086
	if expirationInDays == 0 {
		expirationInDays = 4086
	}

	// If the expiration in days is less than 0, error out
	if expirationInDays < 0 {
		panic("The expiration in days must be greater than or equal to 0")
	}

	configuration.GenerateIntermediateCertificateConfigurationFileIfNotExists(intCert)

	caChainPasswordFilename, err := helper.WritePasswordFile("chain", caChainName, "normal", caChainPassword)
	if err != nil {
		panic(err)
	}
	intCertPasswordFilename, err := helper.WritePasswordFile("intermediate", intCertName, "normal", intCertPassword)
	if err != nil {
		panic(err)
	}
	intCertPfxPasswordFilename, err := helper.WritePasswordFile("intermediate", intCertName, "pfx", intCertPfxPassword)
	if err != nil {
		panic(err)
	}

	// Get command text
	command := fmt.Sprintf("./ssl/generate-intermediate-ca.sh %s @%s @%s %s @%s %s %s %s %s %d %d", intCertName, intCertPasswordFilename, intCertPfxPasswordFilename, caChainName, caChainPasswordFilename, isLastChainRootCa, shouldInsertIntoTrustedStore, skipDhParam, keepCertificateRequestFile, expirationInDays, keyLength)

	// Execute the command
	helper.ExecuteRawCommand(command)

	// Add the root certificate to the map
	loadedIntCerts[caChainName] = intCert

	defer helper.DeleteTmpPasswords([]string{caChainPasswordFilename, intCertPasswordFilename, intCertPfxPasswordFilename})
}
