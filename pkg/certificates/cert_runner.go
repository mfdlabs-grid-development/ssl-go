package certificates

import "git.mfdlabs.local/petko/mfdlabs-ssl-go/pkg/configuration"

func Run(configFilePath string, conf *configuration.SslConfiguration, loadedRootCerts map[string]*configuration.RootCertificateAuthority, loadedIntermediateCerts map[string]*configuration.IntermediateCertificateAuthority) {
	// Root certificates first
	LoadRootCertificates(configFilePath, conf, loadedRootCerts)
	LoadIntermediateCertificates(configFilePath, conf, loadedIntermediateCerts)
	LoadLeafCertificates(configFilePath, conf, loadedIntermediateCerts)
}
