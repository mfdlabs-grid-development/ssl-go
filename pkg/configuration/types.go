package configuration

type SslConfiguration struct {
	// A list of root certificates to generate the certificate chain.
	RootCertificateAuthorities []*RootCertificateAuthority `json:"rootCa" yaml:"root_ca"`

	// A list of intermediate certificates to generate the certificate chain.
	IntermediateCertificateAuthorities []*IntermediateCertificateAuthority `json:"intermediateCa" yaml:"intermediate_ca"`

	// A list of leaf certificates to generate the certificate chain.
	LeafCertificateAuthorities []*LeafCertificate `json:"leafCertificate" yaml:"leaf_certificate"`
}

type RootCertificateAuthority struct {
	// If this is is specified, it will try to load the generation config from the specified file,
	// whether it is absolute or relative to the root configuration file.
	ReferencedConfigurationPath string `json:"$ref" yaml:"$ref"`

	// The name of the certificate to generate.
	RootCertificateName string `json:"name" yaml:"name"`

	// The password to the certificate to generate.
	RootCertificatePassword string `json:"password" yaml:"password"`

	// The password for the pkcs12 pfx to generate.
	RootCertificatePfxPassword string `json:"pfxPassword" yaml:"pfx_password"`

	// Determines if for this generation, this root CA should load a configuration file, or if it should prompt the generation parameters from openssl
	HasExtensionFile bool `json:"hasExtensionFile" yaml:"has_extension_file"`

	// Determines if this CA should be added to the trusted root certificate authority store (linux)
	ShouldInsertIntoTrustedStore bool `json:"shouldInsertIntoTrustedStore" yaml:"should_insert_into_trusted_store"`

	// Determines if we should generate DH Parameters for this certificate
	GenerateDHParameters bool `json:"generateDHParam" yaml:"generate_dhparam"`

	// Determines if we should overwrite the ssl configuration if there is one that exists already, with the ConfigurationToGenerate member.
	OverwriteExistingConfiguration bool `json:"overwriteConfig" yaml:"overwrite_config"`

	// A certificate configuration file like openssl.cnf to be generated if the configuration is not found at the bin folder.
	Configuration *BaseCertificateConfiguration `json:"config" yaml:"config"`
}

type IntermediateCertificateAuthority struct {
	// If this is is specified, it will try to load the generation config from the specified file,
	// whether it is absolute or relative to the root configuration file.
	ReferencedConfigurationPath string `json:"$ref" yaml:"$ref"`

	// Determines if the last certificate in the chain is a root certificate authority
	IsLastChainCertificateRootCertificateAuthority bool `json:"isLastChainRootCA" yaml:"is_last_chain_root_ca"`

	// The name of the last certificate in the chain.
	LastChainCertificateName string `json:"caChainName" yaml:"ca_chain_name"`

	// The password to the last certificate in the chain.
	LastChainCertificatePassword string `json:"caChainPassword" yaml:"ca_chain_password"`

	// The name of the intermediate certificate authority to generate.
	IntermediateCertificateAuthorityName string `json:"name" yaml:"name"`

	// The password to the intermediate certificate authority to generate.
	IntermediateCertificateAuthorityPassword string `json:"password" yaml:"password"`

	// The password for the pkcs12 pfx to generate.
	IntermediateCertificateAuthorityPfxPassword string `json:"pfxPassword" yaml:"pfx_password"`

	// Determines if this CA should be added to the trusted root certificate authority store (linux)
	ShouldInsertIntoTrustedStore bool `json:"shouldInsertIntoTrustedStore" yaml:"should_insert_into_trusted_store"`

	// Determines if we should generate DH Parameters for this certificate
	GenerateDHParameters bool `json:"generateDHParam" yaml:"generate_dhparam"`

	// Determines if we should keep the certificate request file (.csr)
	KeepCertificateRequestFile bool `json:"keepCertificateRequestFile" yaml:"keep_certificate_request_file"`

	// Determines if we should overwrite the ssl configuration if there is one that exists already, with the ConfigurationToGenerate member.
	OverwriteExistingConfiguration bool `json:"overwriteConfig" yaml:"overwrite_config"`

	// A certificate configuration file like openssl.cnf to be generated if the configuration is not found at the bin folder.
	Configuration *BaseCertificateConfiguration `json:"config" yaml:"config"`
}

type LeafCertificate struct {
	// If this is is specified, it will try to load the generation config from the specified file,
	// whether it is absolute or relative to the root configuration file.
	ReferencedConfigurationPath string `json:"$ref" yaml:"$ref"`

	// Determines if the last certificate in the chain is a root certificate authority
	IsLastChainCertificateRootCertificateAuthority bool `json:"isLastChainRootCA" yaml:"is_ca_root_ca"`

	// The name of the last certificate in the chain.
	LastChainCertificateName string `json:"caName" yaml:"ca_name"`

	// The password to the last certificate in the chain.
	LastChainCertificatePassword string `json:"caPassword" yaml:"ca_password"`

	// The name of the leaf certificate to generate.
	LeafCertificateName string `json:"name" yaml:"name"`

	// The password to the leaf certificate to generate.
	LeafCertificatePassword string `json:"password" yaml:"password"`

	// The password for the pkcs12 pfx to generate.
	LeafCertificatePfxPassword string `json:"pfxPassword" yaml:"pfx_password"`

	// Determines if we should generate DH Parameters for this certificate
	GenerateDHParameters bool `json:"generateDHParam" yaml:"generate_dhparam"`

	// Determines if we should keep the certificate request file (.csr)
	KeepCertificateRequestFile bool `json:"keepCertificateRequestFile" yaml:"keep_certificate_request_file"`

	// Determines if we should overwrite the ssl configuration if there is one that exists already, with the ConfigurationToGenerate member.
	OverwriteExistingConfiguration bool `json:"overwriteConfig" yaml:"overwrite_config"`

	// A certificate configuration file like openssl.cnf to be generated if the configuration is not found at the bin folder.
	Configuration *LeafCertificateConfiguration `json:"config" yaml:"config"`
}

type BaseCertificateConfiguration struct {
	// The country of the certificate to generate. The 'C' field in openssl.conf. If not specified it will not be set on the certificate.
	Country string `json:"country" yaml:"country"`

	// The state of the certificate to generate. The 'ST' field in openssl.conf. If not specified it will not be set on the certificate.
	State string `json:"state" yaml:"state"`

	// The locality of the certificate to generate. The 'L' field in openssl.conf. If not specified it will not be set on the certificate.
	Locality string `json:"locality" yaml:"locality"`

	// The organization of the certificate to generate. The 'O' field in openssl.conf. If not specified it will not be set on the certificate.
	Organization string `json:"organization" yaml:"organization"`

	// The organizational unit of the certificate to generate. The 'OU' field in openssl.conf. If not specified it will not be set on the certificate.
	OrganizationalUnit string `json:"organizationalUnit" yaml:"organizational_unit"`

	// The common name of the certificate to generate. The 'CN' field in openssl.conf. This is required.
	CommonName string `json:"commonName" yaml:"common_name"`

	// The email address of the certificate to generate. The 'emailAddress' field in openssl.conf. If not specified it will not be set on the certificate.
	EmailAddress string `json:"email" yaml:"email"`

	// Determines if this certificate has critical basic constraints
	HasCriticalBasicConstraints bool `json:"criticalBasicConstraints" yaml:"critical_basic_constraints"`

	// Determines if this certificate has critical key usage
	HasCriticalKeyUsage bool `json:"criticalKeyUsage" yaml:"critical_key_usage"`

	// Determines if this certificate has critical extended key usage
	HasCriticalExtendedKeyUsage bool `json:"criticalExtendedKeyUsage" yaml:"critical_extended_key_usage"`

	// Determines if this certificate has critical certificate policies
	HasCriticalCertificatePolicies bool `json:"criticalCertificatePolicies" yaml:"critical_certificate_policies"`

	// Determines if this certificate has critical name constraints
	HasCriticalNameConstraints bool `json:"criticalNameConstraints" yaml:"critical_name_constraints"`

	// An array of of basic constraints to set on the certificate.
	BasicConstraints []string `json:"basicConstraints" yaml:"basic_constraints"`

	// An array of key usages to add to the certificate.
	KeyUsages []string `json:"keyUsages" yaml:"key_usages"`

	// An array of extended key usages to add to the certificate.
	ExtendedKeyUsages []string `json:"extendedKeyUsages" yaml:"extended_key_usages"`

	// An array of certificate policies to add to the certificate.
	CertificatePolicies []string `json:"certificatePolicies" yaml:"certificate_policies"`

	// An array of name constraints to add to the certificate.
	NameConstraints []string `json:"nameConstraints" yaml:"name_constraints"`
}

type LeafCertificateConfiguration struct {
	BaseCertificateConfiguration `yaml:",inline" json:",inline"`

	// Determines if this leaf certificate has critical subject alt names
	HasCriticalSubjectAltNames bool `json:"criticalSubjectAltNames" yaml:"critical_subject_alt_names"`

	// The Subject Alternative Name object to add to the certificate. Represents the SubjectAlternativeNameConfiguration struct
	SubjectAlternativeName *SubjectAlternativeNameConfiguration `json:"subjectAlternativeName" yaml:"subject_alternative_name"`
}

type SubjectAlternativeNameConfiguration struct {
	// A list of DNS names to add to the certificate.
	DNSNames []string `json:"dnsNames" yaml:"dns_names"`

	// A list of email addresses to add to the certificate.
	EmailAddresses []string `json:"emailAddresses" yaml:"email_addresses"`

	// A list of IP addresses to add to the certificate.
	IPAddresses []string `json:"ipAddresses" yaml:"ip_addresses"`

	// A list of URIs to add to the certificate.
	URIs []string `json:"uris" yaml:"uris"`

	// A list of directory names to add to the certificate.
	DirectoryNames []string `json:"directoryNames" yaml:"directory_names"`

	// A list of registered IDs to add to the certificate.
	RegisteredIDs []string `json:"registeredIDs" yaml:"registered_ids"`

	// A list of other names to add to the certificate.
	OtherNames []string `json:"otherNames" yaml:"other_names"`
}
