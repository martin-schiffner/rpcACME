package models

type AcmeError struct {
	Title       string
	Type        string
	Description string
}

func (e AcmeError) Error(statusCode int, instance string) ProblemDetails {
	return ProblemDetails{
		Type:     e.Type,
		Title:    e.Title,
		Status:   statusCode,
		Detail:   e.Description,
		Instance: instance,
	}
}

func ErrorWithTypeDetail(e AcmeError, detail string) ProblemDetails {
	return ProblemDetails{
		Type:   e.Type,
		Detail: detail,
	}
}

// AccountDoesNotExist defines the below set of standard ACME errors
var AccountDoesNotExist = AcmeError{
	Type:        "urn:ietf:params:acme:error:accountDoesNotExist",
	Description: "The request specified an account that does not exist.",
}

var AlreadyRevoked = AcmeError{
	Type:        "urn:ietf:params:acme:error:alreadyRevoked",
	Description: "The request specified a certificate to be revoked that has already been revoked.",
}

var BadCSRError = AcmeError{
	Type:        "urn:ietf:params:acme:error:badCSR",
	Description: "The CSR is unacceptable (e.g., due to a short key or unsupported key type).",
}

var BadNonce = AcmeError{
	Type:        "urn:ietf:params:acme:error:badNonce",
	Title:       "Bad Nonce",
	Description: "The client sent an unacceptable anti-replay nonce.",
}

var BadPublicKey = AcmeError{
	Type:        "urn:ietf:params:acme:error:badPublicKey",
	Description: "The JWS was signed by a public key the server does not know about, or the nonce is not recognized",
}

var BadRevocationReason = AcmeError{
	Type:        "urn:ietf:params:acme:error:badRevocationReason",
	Description: "The revocation reason provided is not allowed by the server",
}

var BadSignatureAlgorithm = AcmeError{
	Type:        "urn:ietf:params:acme:error:badSignatureAlgorithm",
	Description: "The JWS was signed with an algorithm that the server does not support.",
}

var Caa = AcmeError{
	Type:        "urn:ietf:params:acme:error:caa",
	Description: "Certification Authority Authorization (CAA) records prevent the CA from issuing a certificate for the domain.",
}

var Compound = AcmeError{
	Type:        "urn:ietf:params:acme:error:compound",
	Description: "Specific error conditions are indicated in the `subproblems` field.",
}

var Connection = AcmeError{
	Type:        "urn:ietf:params:acme:error:connection",
	Description: "The server could not connect to the domain to validation target.",
}

var Dns = AcmeError{
	Type:        "urn:ietf:params:acme:error:dns",
	Description: "There was a problem with a DNS query during identifier validation.",
}

var ExternalAccountRequired = AcmeError{
	Type:        "urn:ietf:params:acme:error:externalAccountRequired",
	Description: "The request must include a value for the `externalAccountBinding` field.",
}

var IncorrectResponse = AcmeError{
	Type:        "urn:ietf:params:acme:error:incorrectResponse",
	Description: "Response received didn't match the challenge's requirements",
}

var InvalidContact = AcmeError{
	Type:        "urn:ietf:params:acme:error:invalidContact",
	Description: "A contact URL for an account was invalid.",
}

var Malformed = AcmeError{
	Type:        "urn:ietf:params:acme:error:malformed",
	Description: "The request message was malformed.",
}

var OrderNotReady = AcmeError{
	Type:        "urn:ietf:params:acme:error:orderNotReady",
	Description: "The request attempted to finalize an order that is not ready to be finalized.",
}

var RateLimited = AcmeError{
	Type:        "urn:ietf:params:acme:error:rateLimited",
	Description: "The request exceeds a rate limit.",
}

var RejectedIdentifier = AcmeError{
	Type:        "urn:ietf:params:acme:error:rejectedIdentifier",
	Description: "The server will not issue certificates for the identifier provided.",
}

var ServerInternal = AcmeError{
	Type:        "urn:ietf:params:acme:error:serverInternal",
	Title:       "Internal Server Error",
	Description: "The server experienced an internal error.",
}

var Tls = AcmeError{
	Type:        "urn:ietf:params:acme:error:tls",
	Description: "The server received a TLS error during validation.",
}

var Unauthorized = AcmeError{
	Type:        "urn:ietf:params:acme:error:unauthorized",
	Description: "The client lacks sufficient authorization.",
}

var UnsupportedContact = AcmeError{
	Type:        "urn:ietf:params:acme:error:unsupportedContact",
	Description: "A contact URL for an account used an unsupported protocol scheme.",
}

var UnsupportedIdentifier = AcmeError{
	Type:        "urn:ietf:params:acme:error:unsupportedIdentifier",
	Description: "An identifier is of an unsupported type",
}

var UserActionRequired = AcmeError{
	Type:        "urn:ietf:params:acme:error:userActionRequired",
	Description: "Visit the 'instance' URL and take the required action.",
}
