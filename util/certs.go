package util

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

func sha1HashFromBytes(data []byte) (string, error) {
	h := sha1.New()
	h.Write(data)
	fp := h.Sum(nil)

	var buf bytes.Buffer
	for i, f := range fp {
		if i > 0 {
			_, err := fmt.Fprintf(&buf, ":")
			if err != nil {
				return "", err
			}
		}
		_, err := fmt.Fprintf(&buf, "%02X", f)
		if err != nil {
			return "", err
		}
	}

	return buf.String(), nil
}

// CalculateCertFingerprint takes a PEM formatted certificate and returns the SHA1 hash
func CalculateCertFingerprint(pem *pem.Block) string {
	// calculate fingerprint of the PEM
	h, _ := sha1HashFromBytes(pem.Bytes)
	return h
}

// CalculateCertFingerprintByByte takes binary data (e.g. a DER)
// and returns the resulting SHA1 hash
func CalculateCertFingerprintByByte(certBytes []byte) string {
	// calculate fingerprint of the DER
	h, _ := sha1HashFromBytes(certBytes)
	return h
}

func VerifyCsrPem(csrPem string) error {
	if len(csrPem) == 0 {
		return nil
	}

	block, _ := pem.Decode([]byte(csrPem))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return fmt.Errorf("invalid CSR PEM provided")
	}

	_, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return fmt.Errorf("CSR provided cannot be parsed: %v", err)
	}
	return nil
}

type Csr struct {
	CommonName    string
	Sans          map[string]string
	PublicKeySize int
}

func insertLineBreaks(s string, every int) string {
	var result strings.Builder
	for i, r := range s {
		if i > 0 && i%every == 0 {
			result.WriteRune('\n')
		}
		result.WriteRune(r)
	}
	result.WriteRune('\n')
	return result.String()
}

// formatCsrPem takes a single line string (PEM formatted)
// and adds a line break after 64 characters
// to ensure the PEM decode function can properly parse the input
func formatCsrPem(in string) (string, error) {
	csrHeader := "-----BEGIN CERTIFICATE REQUEST-----\n"
	csrFooter := "-----END CERTIFICATE REQUEST-----\n"
	csrPem := csrHeader + insertLineBreaks(in, 64) + csrFooter
	return csrPem, nil
}

// ParseCsr parses a PEM/Base64 encoded Certificate Signing Request and
// returns a map containing the CSR's information
func ParseCsr(csrPem string) (Csr, error) {
	csrClean := csrPem
	if !strings.Contains(csrPem, "-----BEGIN") {
		csrClean, _ = formatCsrPem(csrPem)
	}
	block, _ := pem.Decode([]byte(csrClean))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return Csr{}, fmt.Errorf("invalid CSR PEM provided")
	}

	// parse the CSR
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return Csr{}, fmt.Errorf("CSR provided cannot be parsed: %v", err)
	}

	// parse public key
	pubKey, err := x509.ParsePKIXPublicKey(csr.RawSubjectPublicKeyInfo)
	if err != nil {
		return Csr{}, fmt.Errorf("CSR public key cannot be parsed: %v", err)
	}

	keysize := 0
	switch pubKey := pubKey.(type) {
	case *rsa.PublicKey:
		keysize = pubKey.N.BitLen()
	default:
		return Csr{}, fmt.Errorf("unsupported public key type in CSR, only RSA is supported")
	}

	// prepare SANs
	sans := make(map[string]string)
	var uriItems []string
	for _, uri := range csr.URIs {
		uriItems = append(uriItems, uri.String())
	}

	var ipItems []string
	for _, ip := range csr.IPAddresses {
		ipItems = append(ipItems, ip.String())
	}

	sans["DNS"] = strings.Join(csr.DNSNames, ",")
	sans["IP"] = strings.Join(ipItems, ",")
	sans["Email"] = strings.Join(csr.EmailAddresses, ",")
	sans["URI"] = strings.Join(uriItems, ",")

	return Csr{
		CommonName:    csr.Subject.CommonName,
		Sans:          sans,
		PublicKeySize: keysize,
	}, nil
}

func IsRenewalDue(renewalStart int, certExpiry string) (bool, error) {
	expDate, err := time.Parse(time.RFC822, certExpiry)
	if err != nil {
		return false, err
	}

	expWindowStart := expDate.AddDate(0, 0, -renewalStart)
	if time.Now().UTC().After(expWindowStart) {
		return true, nil
	}
	return false, nil
}
