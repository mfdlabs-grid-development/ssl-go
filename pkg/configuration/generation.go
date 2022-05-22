package configuration

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

func getSharedConfigHeader(conf *BaseCertificateConfiguration) string {
	var configFile string = `[req]
distinguished_name = issued_to_name
req_extensions = config_extensions
prompt = no

[issued_to_name]
`

	if conf.Country != "" {
		if len(conf.Country) > 2 {
			panic("The country code must be 2 characters")
		}

		configFile += fmt.Sprintf("countryName = %s\n", conf.Country)
	}

	if conf.State != "" {
		configFile += fmt.Sprintf("stateOrProvinceName = %s\n", conf.State)
	}

	if conf.Locality != "" {
		configFile += fmt.Sprintf("localityName = %s\n", conf.Locality)
	}

	if conf.Organization != "" {
		configFile += fmt.Sprintf("organizationName = %s\n", conf.Organization)
	}

	if conf.OrganizationalUnit != "" {
		configFile += fmt.Sprintf("organizationalUnitName = %s\n", conf.OrganizationalUnit)
	}

	if conf.CommonName == "" {
		panic("The common name is empty")
	}

	configFile += fmt.Sprintf("commonName = %s\n", conf.CommonName)

	if conf.EmailAddress != "" {
		configFile += fmt.Sprintf("emailAddress = %s\n", conf.EmailAddress)
	}

	return configFile + "\n[config_extensions]\n"
}

func getLeafConfigHead(conf *LeafCertificateConfiguration) string {
	configFile := getSharedConfigHeader(&conf.BaseCertificateConfiguration)

	// Check if key usage is not empty
	if len(conf.KeyUsages) != 0 {
		if conf.HasCriticalKeyUsage {
			// join  the key usages with a comma
			configFile += fmt.Sprintf("keyUsage = critical, %s\n", strings.Join(conf.KeyUsages, ", "))
		} else {
			// join  the key usages with a comma
			configFile += fmt.Sprintf("keyUsage = %s\n", strings.Join(conf.KeyUsages, ", "))
		}
	} else {
		if conf.HasCriticalKeyUsage {
			configFile += "keyUsage = critical, digitalSignature, keyEncipherment\n"
		} else {
			configFile += "keyUsage = digitalSignature, keyEncipherment\n"
		}
	}

	// Check if basic constraints is not empty
	if len(conf.BasicConstraints) != 0 {
		// Check if basic constraints contains CA:TRUE anywhere, as this isn't allowed because this isn't a CA
		// basic contraints is a list of strings, so we can check for the string CA:TRUE
		if strings.Contains(strings.Join(conf.BasicConstraints, " "), "CA:TRUE") {
			panic("Basic constraints cannot contain CA:TRUE")
		}

		if conf.HasCriticalBasicConstraints {
			configFile += fmt.Sprintf("basicConstraints = critical, CA:FALSE, %s\n", strings.Join(conf.BasicConstraints, ", "))
		} else {
			configFile += fmt.Sprintf("basicConstraints = CA:FALSE, %s\n", strings.Join(conf.BasicConstraints, ", "))
		}
	} else {
		if conf.HasCriticalBasicConstraints {
			configFile += "basicConstraints = critical, CA:FALSE\n"
		} else {
			configFile += "basicConstraints = CA:FALSE\n"
		}
	}

	// Check if extended key usage is not empty
	if len(conf.ExtendedKeyUsages) != 0 {
		if conf.HasCriticalExtendedKeyUsage {
			// join  the extended key usages with a comma
			configFile += fmt.Sprintf("extendedKeyUsage = critical, %s\n", strings.Join(conf.ExtendedKeyUsages, ", "))
		} else {
			// join  the extended key usages with a comma
			configFile += fmt.Sprintf("extendedKeyUsage = %s\n", strings.Join(conf.ExtendedKeyUsages, ", "))
		}
	} else {
		if conf.HasCriticalExtendedKeyUsage {
			configFile += "extendedKeyUsage = critical, serverAuth, clientAuth\n"
		} else {
			configFile += "extendedKeyUsage = serverAuth, clientAuth\n"
		}
	}

	// Check if the policies are not empty
	if len(conf.CertificatePolicies) != 0 {
		if conf.HasCriticalCertificatePolicies {
			// join  the policies with a comma
			configFile += fmt.Sprintf("certificatePolicies = critical, %s\n", strings.Join(conf.CertificatePolicies, ", "))
		} else {
			// join  the policies with a comma
			configFile += fmt.Sprintf("certificatePolicies = %s\n", strings.Join(conf.CertificatePolicies, ", "))
		}
	}

	// Check if the certificate name constraints are not empty
	if len(conf.NameConstraints) != 0 {
		if conf.HasCriticalNameConstraints {
			// join  the certificate name constraints with a comma
			configFile += fmt.Sprintf("nameConstraints = critical, %s\n", strings.Join(conf.NameConstraints, ", "))
		} else {
			// join  the certificate name constraints with a comma
			configFile += fmt.Sprintf("nameConstraints = %s\n", strings.Join(conf.NameConstraints, ", "))
		}
	}

	if conf.SubjectAlternativeName != nil {
		hasDomainNames := len(conf.SubjectAlternativeName.DNSNames) != 0
		hasEmailAddresses := len(conf.SubjectAlternativeName.EmailAddresses) != 0
		hasIpAddresses := len(conf.SubjectAlternativeName.IPAddresses) != 0

		if !(hasDomainNames || hasEmailAddresses || hasIpAddresses) {
			return configFile
		}

		if conf.HasCriticalSubjectAltNames {
			configFile += "subjectAltName = critical, @subject_alt_names\n\n[subject_alt_names]\n"
		} else {
			configFile += "subjectAltName = @subject_alt_names\n\n[subject_alt_names]\n"
		}

		if hasDomainNames {
			// Append all DNS names like this: DNS.index = value\n
			for i, dnsName := range conf.SubjectAlternativeName.DNSNames {
				configFile += fmt.Sprintf("DNS.%d = %s\n", i, dnsName)
			}
		}

		if hasEmailAddresses {
			// Append all email addresses like this: Email.index = value\n
			for i, emailAddress := range conf.SubjectAlternativeName.EmailAddresses {
				configFile += fmt.Sprintf("Email.%d = %s\n", i, emailAddress)
			}
		}

		if hasIpAddresses {
			// Append all IP addresses like this: IP.index = value\n
			for i, ipAddress := range conf.SubjectAlternativeName.IPAddresses {
				configFile += fmt.Sprintf("IP.%d = %s\n", i, ipAddress)
			}
		}
	}

	return configFile
}

func getCaConfigHeader(conf *BaseCertificateConfiguration) string {
	configFile := getSharedConfigHeader(conf)

	// Check if key usage is not empty
	if len(conf.KeyUsages) != 0 {
		if conf.HasCriticalKeyUsage {
			// join  the key usages with a comma
			configFile += fmt.Sprintf("keyUsage = critical, %s\n", strings.Join(conf.KeyUsages, ", "))
		} else {
			// join  the key usages with a comma
			configFile += fmt.Sprintf("keyUsage = %s\n", strings.Join(conf.KeyUsages, ", "))
		}
	} else {
		if conf.HasCriticalKeyUsage {
			configFile += "keyUsage = critical, keyCertSign, cRLSign\n"
		} else {
			configFile += "keyUsage = keyCertSign, cRLSign\n"
		}
	}

	// Check if basic constraints is not empty
	if len(conf.BasicConstraints) != 0 {
		if conf.HasCriticalBasicConstraints {
			configFile += fmt.Sprintf("basicConstraints = critical, CA:TRUE, %s\n", strings.Join(conf.BasicConstraints, ", "))
		} else {
			configFile += fmt.Sprintf("basicConstraints = CA:TRUE, %s\n", strings.Join(conf.BasicConstraints, ", "))
		}
	} else {
		if conf.HasCriticalBasicConstraints {
			configFile += "basicConstraints = critical, CA:TRUE\n"
		} else {
			configFile += "basicConstraints = CA:TRUE\n"
		}
	}

	// Check if extended key usage is not empty
	if len(conf.ExtendedKeyUsages) != 0 {
		if conf.HasCriticalExtendedKeyUsage {
			// join  the extended key usages with a comma
			configFile += fmt.Sprintf("extendedKeyUsage = critical, %s\n", strings.Join(conf.ExtendedKeyUsages, ", "))
		} else {
			// join  the extended key usages with a comma
			configFile += fmt.Sprintf("extendedKeyUsage = %s\n", strings.Join(conf.ExtendedKeyUsages, ", "))
		}
	}

	// Check if the policies are not empty
	if len(conf.CertificatePolicies) != 0 {
		if conf.HasCriticalCertificatePolicies {
			// join  the policies with a comma
			configFile += fmt.Sprintf("certificatePolicies = critical, %s\n", strings.Join(conf.CertificatePolicies, ", "))
		} else {
			// join  the policies with a comma
			configFile += fmt.Sprintf("certificatePolicies = %s\n", strings.Join(conf.CertificatePolicies, ", "))
		}
	}

	// Check if the certificate name constraints are not empty
	if len(conf.NameConstraints) != 0 {
		if conf.HasCriticalNameConstraints {
			// join  the certificate name constraints with a comma
			configFile += fmt.Sprintf("nameConstraints = critical, %s\n", strings.Join(conf.NameConstraints, ", "))
		} else {
			// join  the certificate name constraints with a comma
			configFile += fmt.Sprintf("nameConstraints = %s\n", strings.Join(conf.NameConstraints, ", "))
		}
	}

	return configFile
}

func generateLeafCertConfigurationFileIfNotExists(path string, overwrite bool, conf *LeafCertificateConfiguration) error {
	// Check if the configuration file exists or we are overwriting it
	if _, err := os.Stat(path); os.IsNotExist(err) || overwrite {
		// Create the configuration file

		// Get the configuration file header
		configFile := getLeafConfigHead(conf)

		// Write the configuration file
		return ioutil.WriteFile(path, []byte(configFile), os.FileMode(0644))
	}

	return nil
}

func GenerateLeafCertificateConfigurationFileIfNotExists(ca *LeafCertificate) error {
	// Get current path of the executable
	path, err := os.Getwd()

	if err != nil {
		return err
	}

	// Format the configuration file path
	configFilePath := fmt.Sprintf("%s/bin/%s.conf", path, ca.LeafCertificateName)
	return generateLeafCertConfigurationFileIfNotExists(configFilePath, ca.OverwriteExistingConfiguration, ca.Configuration)
}

func generateCaConfigurationFileIfNotExists(path string, overwrite bool, conf *BaseCertificateConfiguration) error {
	// Check if the configuration file exists or we are overwriting it
	if _, err := os.Stat(path); os.IsNotExist(err) || overwrite {
		// Create the configuration file

		// Get the configuration file header
		configFile := getCaConfigHeader(conf)

		// Write the configuration file
		return ioutil.WriteFile(path, []byte(configFile), os.FileMode(0644))
	}

	return nil
}

func GenerateIntermediateCertificateConfigurationFileIfNotExists(ca *IntermediateCertificateAuthority) error {
	// Get current path of the executable
	path, err := os.Getwd()

	if err != nil {
		return err
	}

	// Format the configuration file path
	configFilePath := fmt.Sprintf("%s/bin/ca-%s.conf", path, ca.IntermediateCertificateAuthorityName)
	return generateCaConfigurationFileIfNotExists(configFilePath, ca.OverwriteExistingConfiguration, ca.Configuration)
}

func GenerateRootCertificateConfigurationFileIfNotExists(ca *RootCertificateAuthority) error {
	// Get current path of the executable
	path, err := os.Getwd()

	if err != nil {
		return err
	}

	// Format the configuration file path
	configFilePath := fmt.Sprintf("%s/bin/root-ca-%s.conf", path, ca.RootCertificateName)
	return generateCaConfigurationFileIfNotExists(configFilePath, ca.OverwriteExistingConfiguration, ca.Configuration)
}
