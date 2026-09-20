package models

import "time"

const (
	CHALLENGE_TYPE_HTTP01 = "http-01"
	CHALLENGE_TYPE_DNS01  = "dns-01"

	CHALLENGE_PENDING    = "pending"
	CHALLENGE_PROCESSING = "processing"
	CHALLENGE_VALID      = "valid"
	CHALLENGE_INVALID    = "invalid"
)

type Challenge struct {
	ChallengeId string          `json:"challengeId" bson:"challengeId"`
	AuthId      string          `json:"authId" bson:"authId"`
	AccountId   string          `json:"accountId" bson:"accountId"`
	Type        string          `json:"type"`
	Url         string          `json:"url"`
	Status      string          `json:"status"`
	Validated   time.Time       `json:"validated"`
	Token       string          `json:"token"`
	Error       string          `json:"error,omitempty"`
	CreatedAt   time.Time       `json:"createdAt" bson:"createdAt"`
	ExpiresAt   time.Time       `json:"expiresAt" bson:"expiresAt"`
	Identifier  OrderIdentifier `json:"identifier" bson:"identifier"`
}

type ChallengeResponse struct {
	Type      string         `json:"type"`
	Url       string         `json:"url"`
	Token     string         `json:"token"`
	Validated time.Time      `json:"validated,omitempty"`
	Status    string         `json:"status"`
	Error     ProblemDetails `json:"error,omitempty,omitzero"`
}
