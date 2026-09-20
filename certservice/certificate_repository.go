package certservice

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	certuimodel "rpcca/acme/models"
	"rpcca/acme/rpcserver"
	"time"

	fiberlog "github.com/gofiber/fiber/v3/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type mongoRepository struct {
	mongoInstance *certuimodel.MongoInstance
	rpcServer     *certuimodel.RpcInstance
}

func NewCertificateRepository(mongoInstance *certuimodel.MongoInstance, rpc *certuimodel.RpcInstance) CertificateRepository {
	return &mongoRepository{
		mongoInstance: mongoInstance,
		rpcServer:     rpc,
	}
}

func (m *mongoRepository) GetTotalNumCerts(ctx context.Context, filter map[string]string, orFilter map[string][]string) (int64, error) {
	client := rpcserver.NewRPCCA_RPCClient(m.rpcServer.Client)

	var filterFields []*rpcserver.KeyValueInfo
	var orFilterFields []*rpcserver.KeyValueInfo

	for key, value := range filter {
		filterFields = append(filterFields, &rpcserver.KeyValueInfo{Key: key, Value: value})
	}
	for key, value := range orFilter {
		for _, item := range value {
			if len(item) > 0 {
				orFilterFields = append(orFilterFields, &rpcserver.KeyValueInfo{Key: key, Value: item})
			}
		}
	}

	certFilter := rpcserver.CertFilter{
		FilterFields:   filterFields,
		OrFilterFields: orFilterFields,
	}

	reply, err := client.GetCertCount(ctx, &certFilter)

	if err != nil {
		fiberlog.Error("error getting certificate count: ", err)
		return 0, err
	}

	return reply.GetResult(), nil
}

func (m *mongoRepository) GetCertificates(ctx context.Context, filter map[string]string, orFilter map[string][]string, fields []string, orderBy string, orderDir int, limit int64, skip int64) (*CertificateListResponse, error) {
	var certificates []Certificate
	certificatesResponse := CertificateListResponse{
		Certificates:     certificates,
		NumTotalCerts:    0,
		NumFilteredCerts: 0,
	}

	client := rpcserver.NewRPCCA_RPCClient(m.rpcServer.Client)

	var filterFields []*rpcserver.KeyValueInfo
	var orFilterFields []*rpcserver.KeyValueInfo

	for key, value := range filter {
		filterFields = append(filterFields, &rpcserver.KeyValueInfo{Key: key, Value: value})
	}
	for key, value := range orFilter {
		for _, item := range value {
			orFilterFields = append(orFilterFields, &rpcserver.KeyValueInfo{Key: key, Value: item})
		}
	}

	certFilter := rpcserver.CertFilter{
		FilterFields:   filterFields,
		OrFilterFields: orFilterFields,
	}

	// paging
	certFilter.Limit = int32(limit)
	certFilter.Offset = int32(skip)

	// sorting
	certFilter.OrderBy = orderBy
	certFilter.OrderDirection = int32(orderDir)

	certList, err := client.GetCertList(ctx, &certFilter)

	if err != nil {
		fiberlog.Error("error getting certificate details: ", err)
		return &certificatesResponse, err
	}

	rpcCerts := certList.GetCertificates()

	for _, rpcCert := range rpcCerts {
		certificates = append(certificates, Certificate{
			CommonName:      rpcCert.GetCommonName(),
			CertFingerprint: rpcCert.GetCertFingerprint(),
			CertTemplate:    rpcCert.GetTemplateName(),
			CertSerial:      rpcCert.GetCertSerial(),
			CaName:          rpcCert.GetCaName(),
			IssuerDn:        rpcCert.GetIssuerDn(),
			NotAfter:        rpcCert.GetNotAfter().AsTime().Format(time.RFC3339),
			NotBefore:       rpcCert.GetNotBefore().AsTime().Format(time.RFC3339),
		})
	}

	certificatesResponse.Certificates = certificates
	certificatesResponse.NumTotalCerts = certList.TotalCertCount
	certificatesResponse.NumFilteredCerts = certList.FilteredCertCount

	return &certificatesResponse, nil
}

func (m *mongoRepository) GetCertificateDetails(ctx context.Context, f CertificateFilter) (Certificate, error) {
	client := rpcserver.NewRPCCA_RPCClient(m.rpcServer.Client)

	var filterFields []*rpcserver.KeyValueInfo
	var orFilterFields []*rpcserver.KeyValueInfo
	var sanFilter []*rpcserver.San

	for key, value := range f.Fields {
		filterFields = append(filterFields, &rpcserver.KeyValueInfo{Key: key, Value: value})
	}
	for key, value := range f.OrFields {
		for _, item := range value {
			orFilterFields = append(orFilterFields, &rpcserver.KeyValueInfo{Key: key, Value: item})
		}
	}
	for _, san := range f.CertificateSans {
		sanFilter = append(sanFilter, &rpcserver.San{
			Type: san.SanType,
			Name: san.SanValue,
		})
	}

	certFilter := rpcserver.CertFilter{
		FilterFields:   filterFields,
		OrFilterFields: orFilterFields,
		Sans:           sanFilter,
	}

	rpcCert, err := client.GetCertDetailsByFilter(ctx, &certFilter)
	if status.Code(err) == codes.NotFound {
		// "cert not found" is not treated as an error
		return Certificate{}, nil
	}
	if err != nil {
		// in any other case return the error
		fiberlog.Error("error getting certificate details: ", err)
		return Certificate{}, err
	}

	var cert Certificate
	cert.CaName = rpcCert.GetCaName()
	cert.CertFingerprint = rpcCert.GetCertFingerprint()
	cert.CertSerial = rpcCert.GetCertSerial()
	cert.CommonName = rpcCert.GetCommonName()
	cert.CertSerial = rpcCert.GetCertSerial()
	cert.IssuedDn = rpcCert.GetIssuedDn()
	cert.IssuerDn = rpcCert.GetIssuerDn()
	cert.NotAfter = rpcCert.GetNotAfter().AsTime().Format(time.RFC822)
	cert.NotBefore = rpcCert.GetNotBefore().AsTime().Format(time.RFC822)
	cert.KeyLength = int(rpcCert.GetKeyLength())
	cert.CertTemplate = rpcCert.GetTemplateName()
	cert.CertString = rpcCert.GetCertString()
	cert.Cdps = rpcCert.GetCdps()
	cert.CertPem = rpcCert.GetCertString()
	cert.CertStatus = rpcCert.GetStatus()

	// populate metadata
	metadataObj := rpcCert.GetMetadata()

	if metadataObj != nil {
		cert.CertMetadata = make(map[string]string)
		for _, kvpair := range rpcCert.Metadata {
			tmpstr := kvpair.GetKey()
			tmpValue := kvpair.GetValue()
			cert.CertMetadata[tmpstr] = tmpValue
		}
	}

	// populate certificate's subject alternative names
	sans := rpcCert.GetSans()

	if sans != nil {
		for _, sanEntry := range rpcCert.Sans {
			tmpSanType := sanEntry.Type
			tmpSanValue := sanEntry.Name
			cert.CertSans = append(cert.CertSans, CertificateSan{SanType: tmpSanType, SanValue: tmpSanValue})
		}
	}
	return cert, nil
}

func (m *mongoRepository) RequestCert(ctx context.Context, certRequest CertificateRequest) (CertificateKeyResponse, error) {
	client := rpcserver.NewRPCCA_RPCClient(m.rpcServer.Client)
	var request rpcserver.CertRequest
	sans := make([]*rpcserver.San, 5)
	metadata := make([]*rpcserver.KeyValueInfo, 5)

	// populate metadata
	i := 0
	for key, value := range certRequest.Metadata {
		var m rpcserver.KeyValueInfo
		m.Key = key
		m.Value = value

		metadata[i] = &m

		i = i + 1
	}

	// populate SANs
	i = 0
	for _, sanEntry := range certRequest.Sans {
		var san rpcserver.San
		san.Type = sanEntry.SanType
		san.Name = sanEntry.SanValue
		sans[i] = &san
	}

	request.KeySize = int32(certRequest.KeySize)
	request.CaName = certRequest.CaName
	request.CommonName = certRequest.Cn
	request.Pkcs10 = certRequest.Csr
	request.KeyType = certRequest.KeyType
	request.TemplateName = certRequest.TemplateName
	request.Kvinfo = metadata
	request.Sans = sans

	var ret CertificateKeyResponse
	if len(certRequest.Csr) > 0 {
		response, err := client.RequestCert(ctx, &request)

		if err != nil {
			return ret, err
		}

		ret.Certificate = response.Cert
	} else {
		response, err := client.RequestKeyCert(ctx, &request)

		if err != nil {
			return ret, err
		}

		ret.Certificate = response.Cert
		ret.PrivateKey = response.Key
		ret.PrivateKeyPassphrase = response.Passphrase
	}

	return ret, nil
}

func (m *mongoRepository) RevokeCert(ctx context.Context, revokeRequest RevokeCerRequest) error {
	client := rpcserver.NewRPCCA_RPCClient(m.rpcServer.Client)
	var request rpcserver.RevokeCertRequest

	request.CertFingerprint = revokeRequest.CertFingerprint
	request.RevocationReason = revokeRequest.Reason
	request.CaName = revokeRequest.CaName
	request.RevocationDate = timestamppb.Now()

	reply, err := client.RevokeCert(ctx, &request)
	if err != nil {
		return err
	}

	if reply.GetResult() != 0 {
		return errors.New("error revoking certificate, RPC returned non-zero")
	}

	return nil
}

func (m *mongoRepository) DownloadKey(ctx context.Context, privKeyRequest PrivateKeyDownloadRequest) (string, error) {
	client := rpcserver.NewRPCCA_RPCClient(m.rpcServer.Client)

	// make SHA-256 of the passphrase
	h := sha256.New()
	h.Write([]byte(privKeyRequest.Passphrase))
	passphraseHash := base64.StdEncoding.EncodeToString(h.Sum(nil))

	req := rpcserver.KeyRetreivalRequest{
		CertFingerprint: privKeyRequest.CertFingerprint,
		PassphraseHash:  passphraseHash,
		OutFormat:       privKeyRequest.OutFormat,
		CaName:          privKeyRequest.CaName,
	}

	keyCertReply, err := client.GetPrivKey(ctx, &req)

	if err != nil {
		fiberlog.Error("error getting private key: ", err)
		return "", err
	}

	return keyCertReply.Key, nil
}

func (m *mongoRepository) GetCertCaChain(ctx context.Context, certFingerprint string) ([]Certificate, error) {
	client := rpcserver.NewRPCCA_RPCClient(m.rpcServer.Client)

	fp := rpcserver.CertificateFingerprint{
		CertFingerprint: certFingerprint,
	}

	rpcCertList, err := client.GetCaChainForCert(ctx, &fp)

	if err != nil {
		fiberlog.Error("error getting CA chain: ", err)
		return nil, err
	}

	var certList []Certificate

	for _, rpcCert := range rpcCertList.GetCert() {
		certList = append(certList, Certificate{
			CommonName:      rpcCert.GetCommonName(),
			CertFingerprint: rpcCert.GetCertFingerprint(),
			CertTemplate:    rpcCert.GetTemplateName(),
			CertSerial:      rpcCert.GetCertSerial(),
			CaName:          rpcCert.GetCaName(),
			IssuerDn:        rpcCert.GetIssuerDn(),
			NotAfter:        rpcCert.GetNotAfter().AsTime().Format(time.RFC3339),
			NotBefore:       rpcCert.GetNotBefore().AsTime().Format(time.RFC3339),
			CertPem:         rpcCert.GetCertString(),
		})
	}

	return certList, nil
}
