package models

import "time"

const (
	AUTHORIZATION_PENDING     = "pending"
	AUTHORIZATION_VALID       = "valid"
	AUTHORIZATION_INVALID     = "invalid"
	AUTHORIZATION_DEACTIVATED = "deactivated"
	AUTHORIZATION_EXPIRED     = "expired"
	AUTHORIZATION_REVOKED     = "revoked"
)

type Authorization struct {
	AuthId     string      `json:"authId" bson:"authId"`
	Status     string      `json:"status"`
	CreatedAt  time.Time   `json:"createdAt" bson:"createdAt"`
	ExpiresAt  time.Time   `json:"expiresAt" bson:"expiresAt"`
	Challenges []Challenge `json:"challenges"`
	OrderId    string      `json:"orderId" bson:"orderId"`
	AccountId  string      `json:"accountId" bson:"accountId"`
	Wildcard   bool        `json:"wildcard,omitempty"`
}
