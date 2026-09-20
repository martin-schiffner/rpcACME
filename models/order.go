package models

import "time"

const (
	ORDER_PENDING    = "pending"
	ORDER_PROCESSING = "processing"
	ORDER_READY      = "ready"
	ORDER_VALID      = "valid"
	ORDER_INVALID    = "invalid"

	IDENTIFIER_TYPE_DNS = "dns"
	IDENTIFIER_TYPE_IP  = "ip"
)

type OrderIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type OrderPayload struct {
	OrderIdentifiers []OrderIdentifier `json:"identifiers"`
	NotBefore        string            `json:"notBefore,omitempty"`
	NotAfter         string            `json:"notAfter,omitempty"`
}

type CsrPayload struct {
	Csr string `json:"csr"`
}

type Order struct {
	OrderId          string            `json:"orderId" bson:"orderId"`
	AccountId        string            `json:"accountId" bson:"accountId"`
	Status           string            `json:"status"`
	CreatedAt        time.Time         `json:"createdAt" bson:"createdAt"`
	Expires          time.Time         `json:"expires"`
	OrderIdentifiers []OrderIdentifier `json:"identifiers" bson:"orderIdentifiers"`
	NotBefore        time.Time         `json:"notBefore,omitempty"`
	NotAfter         time.Time         `json:"notAfter,omitempty"`
	Authorizations   []string          `json:"authorizations"`
	Finalize         string            `json:"finalize"`
	CertUrl          string            `json:"cert,omitempty" bson:"cert"`
	CertId           string            `json:"certId,omitempty" bson:"certId"`
	JobId            int64             `json:"jobId,omitempty" bson:"jobId"`
}

type OrderList struct {
	Orders []string `json:"orders"`
}
