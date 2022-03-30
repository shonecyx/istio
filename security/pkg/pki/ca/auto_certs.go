package ca

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	caerror "istio.io/istio/security/pkg/pki/error"
	"istio.io/istio/security/pkg/pki/util"
)

var (
	AutoCertPrefix = "auto://"
)

func parseAutoCAResourceName(resourceName string) (commonName string, subjectIDs []string, err error) {

	s := strings.TrimPrefix(resourceName, AutoCertPrefix)
	parts := strings.Split(s, "~")

	if len(parts) > 0 {
		commonName = parts[0]
		subjectIDs = append(subjectIDs, parts...)
	}

	return commonName, subjectIDs, nil
}

// following function is used for self-signing istio-proxy CSR sign requests to be enable TLS termination on sidecar outbound listener
// by using tls.credentialName as DNS name i.e 'auto://fake.ebay.com' upon Sidecar object, will initiate auto CA cert self-sign
func CSRSignAutoCACert(resourceName string, csrPEM []byte,
	signingCert *x509.Certificate, signingKey *crypto.PrivateKey, ttl time.Duration) ([]byte, error) {

	csr, err := util.ParsePemEncodedCSR(csrPEM)
	if err != nil {
		return nil, caerror.NewError(caerror.CSRError, err)
	}

	cn, subjectIDs, err := parseAutoCAResourceName(resourceName)
	if err != nil {
		return nil, err
	}

	csr.Subject.CommonName = cn
	csr.Subject.Organization = []string{}

	certBytes, err := util.GenCertFromCSR(csr, signingCert, csr.PublicKey, *signingKey, subjectIDs, ttl, false, true)
	if err != nil {
		return nil, fmt.Errorf("failed to generate cert from CSR: %+v", err)
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	signedCert := pem.EncodeToMemory(block)

	return signedCert, nil
}

func GetAutoCAKeyCertBundleFromFile(path string) (*util.KeyCertBundle, error) {

	//TODO should be used as an additional function in agent init
	//TODO: read from memory (use CLI args to read from file)
	certBytes, err := ioutil.ReadFile(path + "/" + "istio-auto-root-ca-cert.pem")
	if err != nil {
		return nil, err
	}
	//TODO: read from memory (use CLI args to read from file)
	privKeyBytes, err := ioutil.ReadFile(path + "/" + "istio-auto-root-ca-key.pem")
	if err != nil {
		return nil, err
	}

	kcb := util.NewKeyCertBundleFromPem(certBytes, privKeyBytes, nil, nil)

	return kcb, nil

}
