package models

import "time"

type Certificate struct {
	CertId          string    `json:"certificateId" bson:"certificateId"`
	OrderId         string    `json:"orderId" bson:"orderId"`
	AccountId       string    `json:"accountId" bson:"accountId"`
	CreatedAt       time.Time `json:"createdAt" bson:"createdAt"`
	CertPem         string    `json:"certificate" bson:"certificate"`
	CertChain       string    `json:"chain,omitempty" bson:"chain,omitempty"`
	CertFingerprint string    `json:"fingerprint" bson:"fingerprint"`
}

type CertificateRevokePayload struct {
	Certificate string `json:"certificate"`
	Reason      int    `json:"reason,omitempty"`
}
