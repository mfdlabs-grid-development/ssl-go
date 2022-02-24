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

	fmt.Printf("Loading intermediate certificate authority: %s\n", intCertName)

	if err != nil {
		panic(err)
	}

	// Check if the required fields are empty
	if caChainName == "" {
		panic("The ca chain certificate authority name is empty")
	}

	// Chain cannot be the same as the int cert if it's not a Root CA
	if intCertName == caChainName {
		if !intCert.IsLastChainCertificateRootCertificateAuthority {
			panic("The ca chain certificate authority name cannot be the same as the int certificate authority name if it's not a Root CA")
		}
	}

	if caChainPassword == "" {
		panic("The ca chain certificate authority password is empty")
	}

	// Check if password is less than 8 characters
	if len(caChainPassword) < 8 {
		panic("The root certificate authority password is less than 8 characters")
	}

	if intCertName == "" {
		panic("The intermediate certificate authority name is empty")
	}

	// Check if password is less than 8 characters
	if len(intCertPassword) < 8 {
		panic("The intermediate certificate authority password is less than 8 characters")
	}

	// Check if password is less than 8 characters
	if len(intCertPfxPassword) < 8 {
		panic("The intermediate certificate authority pfx password is less than 8 characters")
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

	configuration.GenerateIntermediateCertificateConfigurationFileIfNotExists(intCert)

	// Get command text
	command := fmt.Sprintf("./ssl/generate-intermediate-ca.sh %s %s %s %s %s %s %s %s %s", isLastChainRootCa, caChainName, caChainPassword, intCertName, intCertPassword, intCertPfxPassword, shouldInsertIntoTrustedStore, skipDhParam, keepCertificateRequestFile)

	// Execute the command
	helper.ExecuteRawCommand(command)

	// Add the root certificate to the map
	loadedIntCerts[caChainName] = intCert
}
