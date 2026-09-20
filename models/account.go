package models

const (
	ACCOUNT_VALID       = "valid"
	ACCOUNT_DEACTIVATED = "deactivated"
	ACCOUNT_REVOKED     = "revoked"

	MAX_CONTACTS = 15
)

type Jwk struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
}

type ExternalAccountBinding struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type EabProtected struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Url string `json:"url"`
}

type AccountRequest struct {
	Protected string `json:"protected"`
	Signature string `json:"signature"`
	Payload   string `json:"payload"`
}

type AccountPayload struct {
	Contact        []string               `json:"contact"`
	AgreedTos      bool                   `json:"termsOfServiceAgreed"`
	Status         string                 `json:"status,omitempty"`
	Eab            ExternalAccountBinding `json:"externalAccountBinding"`
	ReturnExisting bool                   `json:"onlyReturnExisting"`
}

type Account struct {
	Status            string   `json:"status"`
	CreatedAt         string   `json:"createdAt" bson:"createdAt"`
	Realm             string   `json:"realm"`
	AccountIdentifier string   `json:"accountIdentifier" bson:"accountIdentifier"`
	Jwk               string   `json:"key" bson:"key"`
	Contact           []string `json:"contact"`
	AgreedTos         bool     `json:"termsOfServiceAgreed" bson:"termsOfServiceAgreed"`
}

type AccountResponse struct {
	Status    string   `json:"status"`
	Contact   []string `json:"contact"`
	OrdersUrl string   `json:"orders"`
}

type AccountIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}
