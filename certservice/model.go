package certservice

import (
	"context"

	"go.mongodb.org/mongo-driver/v2/bson"
)

type CertificateSan struct {
	SanType  string `json:"san_type"`
	SanValue string `json:"san_value"`
}

type CertificateFilter struct {
	Fields          map[string]string
	OrFields        map[string][]string
	CertificateSans []CertificateSan
}

type Certificate struct {
	ID              bson.ObjectID     `bson:"_id" json:"_id" alias:"ID"`
	AuthorityKeyId  string            `bson:"authority_key_id,omitempty" json:"authority_key_id" alias:"Authority Key ID"`
	CaName          string            `bson:"ca_name,omitempty" json:"ca_name" alias:"CA Name"`
	CertPem         string            `bson:"cert_pem,omitempty" json:"cert_pem" alias:"Cert PEM"`
	CertFingerprint string            `bson:"cert_fingerprint,omitempty" json:"cert_fingerprint" alias:"Fingerprint"`
	CertTemplate    string            `bson:"cert_template,omitempty" json:"cert_template" alias:"Template"`
	CertSerial      string            `json:"cert_serial" alias:"Serial"`
	CertStatus      string            `json:"cert_status" alias:"Status"`
	CommonName      string            `bson:"common_name,omitempty" json:"common_name" alias:"Common Name"`
	IssuedDn        string            `bson:"issued_dn,omitempty" json:"issued_dn" alias:"Issued DN"`
	IssuerDn        string            `bson:"issuer_dn,omitempty" json:"issuer_dn" alias:"Issuer DN"`
	NotBefore       string            `bson:"not_before,omitempty" json:"not_before" alias:"Not Before"`
	NotAfter        string            `bson:"not_after,omitempty" json:"not_after" alias:"Not After"`
	SigAlgo         string            `json:"sig_algo" alias:"Signature Algorithm"`
	CertMetadata    map[string]string `json:"cert_metadata" alias:"Certificate Metadata"`
	CertSans        []CertificateSan  `json:"cert_sans"`
	KeyLength       int               `json:"key_length" alias:"Key Length"`
	CertString      string            `json:"cert_string"`
	Cdps            []string          `json:"cdps" alias:"CRL Distribution Points"`
}

type CertificateListResponse struct {
	Certificates     []Certificate
	NumTotalCerts    int64
	NumFilteredCerts int64
}

type AccountLimit struct {
	MaxCerts           int
	MetadataIdentifier []string
}

type CertificateRequest struct {
	CaName        string `validate:"required,ascii"`
	Csr           string
	Cn            string `validate:"required"`
	TemplateName  string `validate:"required"`
	KeySize       int    `validate:"oneof=0 2048 3072 4096"`
	Sans          []CertificateSan
	KeyType       string `validate:"eq=rsa"`
	Metadata      map[string]string
	Requestor     string `validate:"required,email"`
	RequestId     string `validate:"required"`
	AccountLimits AccountLimit
}

type RevokeCerRequest struct {
	CertFingerprint string
	Reason          string
	CaName          string
}

type PrivateKeyDownloadRequest struct {
	CertFingerprint string
	Passphrase      string
	OutFormat       int32 // 0 = PKCS8
	CaName          string
	UserMail        string
}

type CertificateKeyResponse struct {
	Certificate          string
	PrivateKey           string
	PrivateKeyPassphrase string
}

type CertificateRepository interface {
	GetTotalNumCerts(ctx context.Context, filter map[string]string, orFilter map[string][]string) (int64, error)
	GetCertificateDetails(ctx context.Context, f CertificateFilter) (Certificate, error)
	GetCertificates(ctx context.Context, filter map[string]string, orFilter map[string][]string, fields []string, orderBy string, orderDir int, limit int64, skip int64) (*CertificateListResponse, error)
	RequestCert(ctx context.Context, certRequest CertificateRequest) (CertificateKeyResponse, error)
	RevokeCert(ctx context.Context, revokeRequest RevokeCerRequest) error
	DownloadKey(ctx context.Context, privKeyRequest PrivateKeyDownloadRequest) (string, error)
	GetCertCaChain(ctx context.Context, certFingerprint string) ([]Certificate, error)
}
