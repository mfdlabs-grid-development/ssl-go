package certificates

import (
	"fmt"

	"git.mfdlabs.local/petko/mfdlabs-ssl-go/pkg/configuration"
	"git.mfdlabs.local/petko/mfdlabs-ssl-go/pkg/helper"
)

func LoadLeafCertificates(configFilePath string, conf *configuration.SslConfiguration, loadedIntCerts map[string]*configuration.IntermediateCertificateAuthority) {
	// check if the leaf certificates are empty
	if len(conf.LeafCertificateAuthorities) != 0 {
		// load the leaf certificates
		for _, leafCert := range conf.LeafCertificateAuthorities {
			loadLeafCertificate(configFilePath, leafCert, loadedIntCerts, conf.IntermediateCertificateAuthorities)
		}
	}
}

func loadLeafCertificate(configFilePath string, leafCert *configuration.LeafCertificate, loadedIntCerts map[string]*configuration.IntermediateCertificateAuthority, intCerts []*configuration.IntermediateCertificateAuthority) {
	err := DetermineIfLeafCertificateIsReference(configFilePath, leafCert)

	caChainName := helper.ReplaceEnvironmentExpression(leafCert.LastChainCertificateName)
	caChainPassword := helper.ReplaceEnvironmentExpression(leafCert.LastChainCertificatePassword)
	leafCertName := helper.ReplaceEnvironmentExpression(leafCert.LeafCertificateName)
	leafCertPassword := helper.ReplaceEnvironmentExpression(leafCert.LeafCertificatePassword)
	leafCertPfxPassword := helper.ReplaceEnvironmentExpression(leafCert.LeafCertificatePfxPassword)

	// check if the root certificate is already loaded
	if _, ok := loadedIntCerts[caChainName]; ok {
		return
	}

	fmt.Printf("Loading leaf certificate: %s\n", leafCertName)

	if err != nil {
		panic(err)
	}

	// Check if the required fields are empty
	if caChainName == "" {
		panic("The chain certificate name cannot be empty")
	}

	// Chain cannot be the same as the int cert if it's not a Root CA
	if leafCertName == caChainName {
		if !leafCert.IsLastChainCertificateRootCertificateAuthority {
			panic("The chain certificate name cannot be the same as the leaf certificate name if it's not a root certificate")
		}
	}

	if caChainPassword == "" {
		panic("The chain certificate password cannot be empty")
	}

	// Check if password is less than 8 characters
	if len(caChainPassword) < 4 {
		panic("The chain certificate password cannot be less than 4 characters")
	}

	if leafCertName == "" {
		panic("The leaf certificate name cannot be empty")
	}

	// Check if password is less than 8 characters
	if len(leafCertPassword) < 4 {
		panic("The leaf certificate password cannot be less than 4 characters")
	}

	// Check if password is less than 8 characters
	if len(leafCertPfxPassword) < 4 {
		panic("The leaf certificate PFX password cannot be less than 4 characters")
	}

	err = helper.CheckCertificateName(caChainName)
	if err != nil {
		panic(err)
	}
	err = helper.CheckCertificateName(leafCertName)
	if err != nil {
		panic(err)
	}

	// Section for generating the ca chain certificate if it's in the config and further down in the code
	if len(intCerts) > 0 && !leafCert.IsLastChainCertificateRootCertificateAuthority {
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
	skipDhParam := helper.Ternary(leafCert.GenerateDHParameters, "NO", "YES").(string)
	keepCertificateRequestFile := helper.Ternary(leafCert.KeepCertificateRequestFile, "YES", "NO").(string)
	isLastChainRootCa := helper.Ternary(leafCert.IsLastChainCertificateRootCertificateAuthority, "YES", "NO").(string)

	keyLength := leafCert.PrivateKeySize

	// If the key length is not set, set it to 2048
	if keyLength == 0 {
		keyLength = 2048
	}

	// If the key length is not 1024, 2048 or 4096, error out
	if keyLength != 1024 && keyLength != 2048 && keyLength != 4096 {
		panic("The key length must be 1024, 2048 or 4096")
	}

	expirationInDays := leafCert.ValidityPeriod

	// If the expiration in days is not set, set it to 4086
	if expirationInDays == 0 {
		expirationInDays = 4086
	}

	// If the expiration in days is less than 0, error out
	if expirationInDays < 0 {
		panic("The expiration in days must be greater than or equal to 0")
	}

	configuration.GenerateLeafCertificateConfigurationFileIfNotExists(leafCert)

	caChainPasswordFilename, err := helper.WritePasswordFile("chain", caChainName, "normal", caChainPassword)
	if err != nil {
		panic(err)
	}
	leafCertPasswordFilename, err := helper.WritePasswordFile("leaf", leafCertName, "normal", leafCertPassword)
	if err != nil {
		panic(err)
	}
	leafCertPfxPasswordFilename, err := helper.WritePasswordFile("leaf", leafCertName, "pfx", leafCertPfxPassword)
	if err != nil {
		panic(err)
	}

	// Get command text
	command := fmt.Sprintf("./ssl/generate-certs-v2.sh %s @%s @%s %s @%s %s %s %s %d %d", leafCertName, leafCertPasswordFilename, leafCertPfxPasswordFilename, caChainName, caChainPasswordFilename, isLastChainRootCa, skipDhParam, keepCertificateRequestFile, expirationInDays, keyLength)

	// Execute the command
	helper.ExecuteRawCommand(command)

	defer helper.DeleteTmpPasswords([]string{caChainPasswordFilename, leafCertPasswordFilename, leafCertPfxPasswordFilename})
}
