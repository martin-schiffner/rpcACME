package util

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/go-jose/go-jose/v4"
)

var allSignatureAlgorithms = []jose.SignatureAlgorithm{
	jose.EdDSA,
	jose.HS256,
	jose.HS384,
	jose.HS512,
	jose.RS256,
	jose.RS384,
	jose.RS512,
	jose.ES256,
	jose.ES384,
	jose.ES512,
	jose.PS256,
	jose.PS384,
	jose.PS512,
}

type JwsParsed struct {
	Algo      string
	Kid       string
	Nonce     string
	Url       string
	Signature string
	Payload   string
	Jwk       string // may be used when signing revoke request with cert's pub key
}

type JwsVerifiedParsed struct {
	KeyThumbprint string
	KeyJson       string
	Payload       []byte
	Nonce         string
}

type JwkParsed struct {
	Keytype string `json:"kty"`
	Curve   string `json:"crv"`
	X       string `json:"x"`
}

func VerifyMessage(in string) (JwsVerifiedParsed, error) {
	parsedVerified := JwsVerifiedParsed{}

	// parsing and validation
	jws, err := jose.ParseSignedJSON(in, allSignatureAlgorithms)
	if err != nil {
		return parsedVerified, err
	}

	if len(jws.Signatures) != 1 {
		return parsedVerified, errors.New("too many or too few signatures")
	}

	sig := jws.Signatures[0]
	if sig.Header.JSONWebKey == nil {
		return parsedVerified, errors.New("no JWK in signature header")
	}

	nonce := sig.Header.Nonce
	if nonce == "" {
		return parsedVerified, errors.New("no nonce in signature header")
	}

	payload, err := jws.Verify(sig.Header.JSONWebKey)
	if err != nil {
		return parsedVerified, err
	}

	// calculate thumbprint of key
	thmb, err := sig.Header.JSONWebKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return parsedVerified, err
	}

	// key to JSON
	key, err := sig.Header.JSONWebKey.MarshalJSON()
	if err != nil {
		return parsedVerified, err
	}

	parsedVerified.Payload = payload
	parsedVerified.KeyThumbprint = base64.RawURLEncoding.EncodeToString(thmb)
	parsedVerified.KeyJson = string(key)
	parsedVerified.Nonce = nonce

	return parsedVerified, nil
}

func ParseJwsHeader(in string) (JwsParsed, error) {
	jwsParsed := JwsParsed{}

	jws, err := jose.ParseSignedJSON(in, allSignatureAlgorithms)
	if err != nil {
		return jwsParsed, err
	}

	jwsParsed.Algo = jws.Signatures[0].Header.Algorithm
	jwsParsed.Kid = jws.Signatures[0].Header.KeyID
	jwsParsed.Nonce = jws.Signatures[0].Header.Nonce
	jwsParsed.Url = jws.Signatures[0].Header.ExtraHeaders["url"].(string)
	jwsParsed.Payload = string(jws.UnsafePayloadWithoutVerification())
	return jwsParsed, nil
}

func VerifySignedMessage(in string, jwk string) (JwsVerifiedParsed, error) {
	parsedVerified := JwsVerifiedParsed{}

	// try marshalling key
	var key jose.JSONWebKey
	err := key.UnmarshalJSON([]byte(jwk))
	if err != nil {
		return JwsVerifiedParsed{}, err
	}

	// parsing and validation
	jws, err := jose.ParseSignedJSON(in, allSignatureAlgorithms)
	if err != nil {
		return JwsVerifiedParsed{}, err
	}

	if len(jws.Signatures) != 1 {
		return JwsVerifiedParsed{}, errors.New("too many or too few signatures")
	}

	sig := jws.Signatures[0]

	nonce := sig.Header.Nonce
	if nonce == "" {
		return JwsVerifiedParsed{}, errors.New("no nonce in signature header")
	}

	// verify signature with given key
	payload, err := jws.Verify(key)
	if err != nil {
		return JwsVerifiedParsed{}, err
	}

	parsedVerified.Payload = payload
	parsedVerified.Nonce = nonce

	return parsedVerified, nil
}

func ParseJwk(in string) (JwkParsed, error) {
	var jwk JwkParsed
	err := json.Unmarshal([]byte(in), &jwk)
	if err != nil {
		return JwkParsed{}, err
	}
	return jwk, nil
}

func GetKeyThumbprint(in string, hashType crypto.Hash) (string, error) {
	var jwk jose.JSONWebKey
	err := json.Unmarshal([]byte(in), &jwk)
	if err != nil {
		return "", errors.New("unable to parse JWK from input string: " + err.Error())
	}

	// calculate the SHA-256 of the account key
	thumbBytes, err := jwk.Thumbprint(hashType)
	if err != nil {
		return "", errors.New("unable to calculate thumbprint of account key: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(thumbBytes), nil
}
