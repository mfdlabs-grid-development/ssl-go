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
		panic("The ca chain certificate authority name is empty")
	}

	// Chain cannot be the same as the int cert if it's not a Root CA
	if leafCertName == caChainName {
		if !leafCert.IsLastChainCertificateRootCertificateAuthority {
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

	if leafCertName == "" {
		panic("The leaf certificate name is empty")
	}

	// Check if password is less than 8 characters
	if len(leafCertPassword) < 8 {
		panic("The leaf certificate password is less than 8 characters")
	}

	// Check if password is less than 8 characters
	if len(leafCertPfxPassword) < 8 {
		panic("The leaf certificate pfx password is less than 8 characters")
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

	configuration.GenerateLeafCertificateConfigurationFileIfNotExists(leafCert)

	// Get command text
	command := fmt.Sprintf("./ssl/generate-certs-v2.sh %s %s %s %s %s %s %s %s", isLastChainRootCa, caChainName, caChainPassword, leafCertName, leafCertPassword, leafCertPfxPassword, skipDhParam, keepCertificateRequestFile)

	// Execute the command
	helper.ExecuteRawCommand(command)
}
