package certservice

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	acmemodel "rpcca/acme/models"
	"rpcca/acme/util"
	"strings"
)

type CertService interface {
	GetTotalNumCerts(ctx context.Context, filter map[string]string, orFilter map[string][]string) (int64, error)
	GetCertificateDetails(ctx context.Context, filter map[string]string, orFilter map[string][]string) (Certificate, error)
	GetCertificates(ctx context.Context, filter map[string]string, orFilter map[string][]string, fields []string, orderBy string, orderDir string, start int64, length int64) (*CertificateListResponse, error)
	GetCertCaChain(ctx context.Context, fingerprint string) ([]Certificate, error)
	HasAccountCert(ctx context.Context, account acmemodel.Account, csr CertificateRequest) (Certificate, error)
	RequestCertificate(ctx context.Context, certRequest CertificateRequest) (CertificateKeyResponse, error)
	RevokeCertificate(ctx context.Context, caName string, certFingerprint string, reason string, filter map[string]string, orFilter map[string][]string) error
	DownloadKey(ctx context.Context, privKeyRequest PrivateKeyDownloadRequest) (string, error)
	CertToFileName(cert Certificate) string
}

type certService struct {
	certificateRepository CertificateRepository
	logger                *slog.Logger
}

func NewCertService(cr CertificateRepository, l *slog.Logger) CertService {
	return &certService{
		certificateRepository: cr,
		logger:                l,
	}
}

func (s *certService) GetTotalNumCerts(ctx context.Context, filter map[string]string, orFilter map[string][]string) (int64, error) {
	numCerts, err := s.certificateRepository.GetTotalNumCerts(ctx, filter, orFilter)

	if err != nil {
		return 0, err
	}

	return numCerts, nil
}

func (s *certService) GetCertificateDetails(ctx context.Context, filter map[string]string, orFilter map[string][]string) (Certificate, error) {
	var cert Certificate

	f := CertificateFilter{
		Fields:          filter,
		OrFields:        orFilter,
		CertificateSans: []CertificateSan{},
	}
	cert, err := s.certificateRepository.GetCertificateDetails(ctx, f)

	if err != nil {
		return cert, err
	}

	return cert, nil
}

func (s *certService) GetCertificates(ctx context.Context, filter map[string]string, orFilter map[string][]string, fields []string, orderBy string, orderDir string, start int64, length int64) (*CertificateListResponse, error) {
	// set default order to ascending
	mongoOrderDir := 1

	if orderDir == "desc" {
		mongoOrderDir = -1

	}
	certs, err := s.certificateRepository.GetCertificates(ctx, filter, orFilter, fields, orderBy, mongoOrderDir, length, start)

	if err != nil {
		return nil, err
	}

	return certs, nil
}

func (s *certService) GetCertCaChain(ctx context.Context, fingerprint string) ([]Certificate, error) {
	caCerts, err := s.certificateRepository.GetCertCaChain(ctx, fingerprint)
	if err != nil {
		return []Certificate{}, err
	}

	return caCerts, nil
}

func (s *certService) HasAccountCert(ctx context.Context, account acmemodel.Account, csr CertificateRequest) (Certificate, error) {
	certFilter := make(map[string]string)
	certFilter["common_name"] = csr.Cn
	certFilter["cert_metadata.acme_contacts"] = account.Contact[0]
	certFilter["cert_metadata.acme_account"] = account.AccountIdentifier
	certFilter["status"] = "issued"

	f := CertificateFilter{
		Fields:          certFilter,
		OrFields:        map[string][]string{},
		CertificateSans: csr.Sans,
	}

	var cert Certificate
	cert, err := s.certificateRepository.GetCertificateDetails(ctx, f)

	if err != nil {
		return cert, err
	}
	return cert, nil
}

func (s *certService) RequestCertificate(ctx context.Context, certRequest CertificateRequest) (CertificateKeyResponse, error) {
	// check if the requested identifiers exist in the metadata
	// populate filter if field is available
	filter := make(map[string]string)
	for _, id := range certRequest.AccountLimits.MetadataIdentifier {
		if _, ok := certRequest.Metadata[id]; !ok {
			return CertificateKeyResponse{}, fmt.Errorf("requested metadata identifier not found in request")
		}

		// populate filter
		filter[id] = certRequest.Metadata[id]
	}

	// ensure the names in the cert are not DNS resolvable
	err := validateNoDns(certRequest)
	if err != nil {
		return CertificateKeyResponse{}, err
	}

	if certRequest.AccountLimits.MaxCerts == 0 {
		// there is no max cert limitation, issue cert right away
		return s.certificateRepository.RequestCert(ctx, certRequest)
	}

	// check number of certs
	// check the limit as per given account identifier
	// get certificate list based on user/acme details
	certCount, err := s.GetTotalNumCerts(ctx, filter, make(map[string][]string))
	if err != nil {
		return CertificateKeyResponse{}, fmt.Errorf("there was an error getting the certificate count: %s", err.Error())
	}

	if certCount >= int64(certRequest.AccountLimits.MaxCerts) {
		// certificate amount of this account reached, return error
		return CertificateKeyResponse{}, fmt.Errorf("cert limit reached, cannot issue certificate")
	}

	// cert amount is within the limit, issue cert
	return s.certificateRepository.RequestCert(ctx, certRequest)
}

func (s *certService) RevokeCertificate(ctx context.Context, caName string, certFingerprint string, reason string, filter map[string]string, orFilter map[string][]string) error {
	f := make(map[string]string)
	f["ca_name"] = caName
	f["cert_fingerprint"] = certFingerprint
	maps.Copy(f, filter)

	certFilter := CertificateFilter{
		Fields:          f,
		OrFields:        orFilter,
		CertificateSans: []CertificateSan{},
	}

	var cert Certificate
	cert, err := s.certificateRepository.GetCertificateDetails(ctx, certFilter)

	if err != nil {
		return err
	}

	if len(cert.CertFingerprint) == 0 {
		return errors.New("no certificate found with the given fingerprint and CA name or you don't have access to it")
	}

	// then revoke cert if everything is ok, otherwise return error
	revokeRequest := RevokeCerRequest{
		CaName:          caName,
		CertFingerprint: certFingerprint,
		Reason:          reason,
	}
	return s.certificateRepository.RevokeCert(ctx, revokeRequest)
}

func (s *certService) DownloadKey(ctx context.Context, privKeyRequest PrivateKeyDownloadRequest) (string, error) {
	key, err := s.certificateRepository.DownloadKey(ctx, privKeyRequest)
	if err != nil {
		return "", err
	}

	return key, nil
}

func (s *certService) CertToFileName(cert Certificate) string {
	if len(cert.CommonName) > 0 {
		fName := strings.Replace(cert.CommonName, ".", "", 200)
		fName = strings.Replace(fName, "-", "", 200)
		fName = strings.Replace(fName, ":", "", 200)
		fName = strings.Replace(fName, " ", "", 200)
		return fName
	}
	return strings.Replace(cert.CertFingerprint, ":", "", 200)
}

func removePrefix(prefix string, s string) string {
	return strings.TrimPrefix(s, prefix)
}

func validateNoDns(request CertificateRequest) error {
	var cnError error

	err := util.ValidateNoDns(removePrefix("CN=", request.Cn))
	if err != nil {
		cnError = err
	}

	// check if CSR is given in the request (could be empty in case of manual cert request)
	if len(request.Csr) != 0 {
		// parse CSR to get the SANs from it
		csrParsed, err := util.ParseCsr(request.Csr)
		if err != nil {
			return fmt.Errorf("could not parse csr: %s", err)
		}

		// check SANs of CSR
		if _, ok := csrParsed.Sans["DNS"]; !ok {
			return errors.Join(cnError, fmt.Errorf("csr does not contain DNS field"))
		}

		if len(csrParsed.Sans["DNS"]) == 0 {
			// empty DNS is fine, return error of CN check (if any)
			return cnError
		}

		dnsList := strings.Split(csrParsed.Sans["DNS"], ",")
		for _, dns := range dnsList {
			if err = util.ValidateNoDns(strings.TrimSpace(dns)); err != nil {
				return errors.Join(cnError, fmt.Errorf("certificate SAN entry is DNS-resolvable: %s", err.Error()))
			}
		}
	}

	// check SANs of request
	for _, san := range request.Sans {
		if san.SanType == "DNS" {
			if err = util.ValidateNoDns(strings.TrimSpace(san.SanValue)); err != nil {
				return errors.Join(cnError, fmt.Errorf("certificate SAN entry is DNS-resolvable: %s", err.Error()))
			}
		}
	}
	return cnError
}
