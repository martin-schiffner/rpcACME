package controllers

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"rpcca/acme/certservice"
	"rpcca/acme/config"
	acme_model "rpcca/acme/models"
	"rpcca/acme/util"
	"rpcca/acme/worker"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/log"
	fiberlog "github.com/gofiber/fiber/v3/log"
)

const (
	ENDPOINT_ORDER   = "order"
	ENDPOINT_AUTHZ   = "authz"
	ENDPOINT_ACCOUNT = "account"
)

type AcmeDirectoryMeta struct {
	Tos                     string   `json:"termsOfService,omitempty"`
	Website                 string   `json:"website,omitempty"`
	CaaIdentities           []string `json:"caaIdentities,omitzero"`
	ExternalAccountRequired bool     `json:"externalAccountRequired"`
}

type AcmeDirectory struct {
	NewNonce   string            `json:"newNonce"`
	NewAccount string            `json:"newAccount"`
	NewOrder   string            `json:"newOrder"`
	RevokeCert string            `json:"revokeCert"`
	KeyChange  string            `json:"keyChange"`
	Meta       AcmeDirectoryMeta `json:"meta,omitempty"`
}

type AcmeController struct {
	certService       certservice.CertService
	acmeService       AcmeService
	config            config.Config
	cryptoService     CryptoService
	dispatcherService *worker.Dispatcher
}

func NewAcmeController(router fiber.Router, cs certservice.CertService, as AcmeService, cryptsvc CryptoService, cfg config.Config, dispatcher *worker.Dispatcher) {
	// set controller struct values
	controller := &AcmeController{
		certService:       cs,
		acmeService:       as,
		config:            cfg,
		cryptoService:     cryptsvc,
		dispatcherService: dispatcher,
	}

	router.Get(":endpoint/directory", controller.AcmeDirectory) // return the ACME directory

	router.Head(":endpoint/new-nonce", controller.NewNonce) // returns a new nonce
	router.Get(":endpoint/new-nonce", controller.NewNonce)  // RFC mandates a GET request to the same endpoint

	router.Post(":endpoint/new-account", controller.NewAccount)                 // creates a new account, returns location of account
	router.Post(":endpoint/account/:accountid", controller.UpdateAccount)       // update account
	router.Post(":endpoint/new-order", controller.NewOrder)                     // take new order request, returns location of order
	router.Post(":endpoint/authz/:authid", controller.Authorization)            // authorization endpoint for orders
	router.Post(":endpoint/account/:accountid/orders", controller.ReturnOrders) // returns a list of orders for the account
	router.Post(":endpoint/challenge/:challengeid", controller.Challenge)       // returns challenges for the order
	router.Post(":endpoint/challenge-response/*", controller.ChallengeResponse) // take challenge response
	router.Post(":endpoint/order/:orderid/finalize", controller.FinalizeOrder)  // finalize an order
	router.Post(":endpoint/order/:orderid", controller.OrderStatus)             // handles order and returns order status
	router.Post(":endpoint/cert/:certid", controller.ReturnCert)                // returns the certificate for an order
	router.Post(":endpoint/revoke-cert", controller.RevokeCert)                 // revokes a certificate
}

func (ctrler *AcmeController) AcmeDirectory(c fiber.Ctx) error {
	endpoint := c.Params("endpoint")
	if _, ok := ctrler.config.AcmeConfig.Endpoints[endpoint]; !ok {
		return c.SendStatus(fiber.StatusNotFound)
	}

	basePath := ctrler.config.HTTP.BaseUrl + "/acme/" + endpoint

	// this ACME servers require an external account binding, prepare meta
	meta := AcmeDirectoryMeta{
		ExternalAccountRequired: true,
	}

	dir := AcmeDirectory{
		NewNonce:   basePath + "/new-nonce",
		NewAccount: basePath + "/new-account",
		NewOrder:   basePath + "/new-order",
		RevokeCert: basePath + "/revoke-cert",
		KeyChange:  basePath + "/key-change",
		Meta:       meta,
	}

	c.Response().Header.Set("Content-Type", "application/json")

	directory, err := json.Marshal(dir)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Error generating ACME directory JSON")
	}

	return c.SendString(string(directory))
}

func (ctrler *AcmeController) NewNonce(c fiber.Ctx) error {
	endpoint := c.Params("endpoint")
	if _, ok := ctrler.config.AcmeConfig.Endpoints[endpoint]; !ok {
		return c.SendStatus(fiber.StatusNotFound)
	}

	log.Infof("client requested new nonce for endpoint %s", endpoint)

	nonce, err := ctrler.getNonceAndStore(c, endpoint)
	if err != nil {
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	c.Response().Header.Set("Cache-Control", "no-store")
	c.Response().Header.Set("Replay-Nonce", nonce)
	c.Response().Header.Set("Link", "<"+ctrler.config.HTTP.BaseUrl+"/directory>; rel=\"index\"")

	// if not a HEAD request, return 200 OK as per RFC 8555
	if c.Method() != fiber.MethodHead {
		c.Response().SetStatusCode(fiber.StatusOK)
		return c.SendStatus(fiber.StatusOK)
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func (ctrler *AcmeController) NewAccount(c fiber.Ctx) error {
	c.Accepts("application/jose+json")

	endpoint := c.Params("endpoint")
	if _, ok := ctrler.config.AcmeConfig.Endpoints[endpoint]; !ok {
		return c.SendStatus(fiber.StatusNotFound)
	}

	// verify JWS
	jws := c.Body()
	jwsParsed, err := util.VerifyMessage(string(jws))
	if err != nil {
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// verify and delete nonce
	err = ctrler.verifyAndDeleteNonce(c, jwsParsed.Nonce)
	if err != nil {
		return ctrler.acmeProblem(c, acme_model.BadNonce, err.Error())
	}

	// parse payload
	var acctPayload acme_model.AccountPayload
	err = json.Unmarshal(jwsParsed.Payload, &acctPayload)
	if err != nil {
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// account id
	accountId := jwsParsed.KeyThumbprint

	if acctPayload.ReturnExisting {
		// client indicates it wants to retrieve the account
		acctUrl, err := ctrler.newEndpointUrl(endpoint, ENDPOINT_ACCOUNT, accountId)
		if err != nil {
			return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
		}

		account, err := ctrler.acmeService.GetAccountById(c.Context(), accountId)
		if err == nil { // account found, return it
			// get new nonce for response
			nonce, err := ctrler.getNonceAndStore(c, endpoint)
			if err != nil {
				return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
			}

			ordersUrl, _ := ctrler.newEndpointUrl(endpoint, ENDPOINT_ACCOUNT+"/order", accountId)

			c.Response().Header.Set("Content-Type", "application/json")
			c.Response().Header.Set("Location", acctUrl)
			c.Response().Header.Set("Replay-Nonce", nonce)
			c.Response().SetStatusCode(fiber.StatusOK)

			acctReturn := struct {
				Status    string   `json:"status"`
				Contact   []string `json:"contact"`
				AgreedTos bool     `json:"termsOfServiceAgreed" bson:"termsOfServiceAgreed"`
				Orders    string   `json:"orders"`
			}{
				Status:    account.Status,
				Contact:   account.Contact,
				AgreedTos: account.AgreedTos,
				Orders:    ordersUrl,
			}
			return c.JSON(acctReturn)
		}
		return ctrler.acmeProblem(c, acme_model.AccountDoesNotExist, "")
	}

	// ensure whether there is External Account Binding contained in this request
	if len(acctPayload.Eab.Protected) <= 0 {
		return ctrler.acmeProblem(c, acme_model.ExternalAccountRequired, "Pre-register your account before.")
	}

	// there is an EAB contained in the request, validate it
	payloadBytes := make([]byte, base64.RawURLEncoding.DecodedLen(len(acctPayload.Eab.Protected)))
	_, err = base64.RawURLEncoding.Decode(payloadBytes, []byte(acctPayload.Eab.Protected))
	if err != nil {
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// unmarshal payload
	var eabProtected acme_model.EabProtected
	err = json.Unmarshal(payloadBytes, &eabProtected)
	if err != nil {
		return ctrler.acmeProblem(c, acme_model.Malformed, "unable to decode external account binding payload"+err.Error())
	}

	// validate...
	// ...number of given contacts
	if len(acctPayload.Contact) > acme_model.MAX_CONTACTS {
		return ctrler.acmeProblem(c, acme_model.Malformed, "too many contacts. max is "+strconv.Itoa(acme_model.MAX_CONTACTS))
	}
	// ...format of contacts
	err = util.IsValidContact(acctPayload.Contact[0])
	if err != nil {
		return ctrler.acmeProblem(c, acme_model.UnsupportedContact, "unsupported or invalid contact: "+acctPayload.Contact[0])
	}

	// handle actual account stuff
	acctUrl, err := ctrler.newEndpointUrl(endpoint, ENDPOINT_ACCOUNT, accountId)
	if err != nil {
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// check, whether the contact is already known or was known
	res, err := ctrler.acmeService.CheckAccountPresence(c.Context(), acctPayload.Contact[0])
	if res {
		return ctrler.acmeProblem(c, acme_model.InvalidContact, "account already known, cannot (re-)register")
	}
	// if known, return the details
	account, err := ctrler.acmeService.GetAccountByContact(c.Context(), acctPayload.Contact[0])
	if err == nil && len(account.AccountIdentifier) > 0 {
		// account know, return it
		nonce, err := ctrler.getNonceAndStore(c, endpoint)
		if err != nil {
			return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
		}

		acctUrl, err := ctrler.newEndpointUrl(endpoint, ENDPOINT_ACCOUNT, account.AccountIdentifier)
		if err != nil {
			return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
		}

		c.Response().Header.Set("Content-Type", "application/json")
		c.Response().Header.Set("Location", acctUrl)
		c.Response().Header.Set("Replay-Nonce", nonce)
		c.Response().SetStatusCode(fiber.StatusOK)

		acctReturn := struct {
			Status    string   `json:"status"`
			Contact   []string `json:"contact"`
			AgreedTos bool     `json:"termsOfServiceAgreed" bson:"termsOfServiceAgreed"`
			Orders    string   `json:"orders"`
		}{
			Status:    account.Status,
			Contact:   account.Contact,
			AgreedTos: account.AgreedTos,
		}
		return c.JSON(acctReturn)
	}

	// check whether account is already known
	account, err = ctrler.acmeService.GetAccountById(c.Context(), accountId)
	if err == nil { // account found, return it
		// get new nonce for response
		nonce, err := ctrler.getNonceAndStore(c, endpoint)
		if err != nil {
			return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
		}

		ordersUrl, _ := ctrler.newEndpointUrl(endpoint, ENDPOINT_ACCOUNT+"/order", accountId)

		c.Response().Header.Set("Content-Type", "application/json")
		c.Response().Header.Set("Location", acctUrl)
		c.Response().Header.Set("Replay-Nonce", nonce)
		c.Response().SetStatusCode(fiber.StatusOK)

		acctReturn := struct {
			Status    string   `json:"status"`
			Contact   []string `json:"contact"`
			AgreedTos bool     `json:"termsOfServiceAgreed" bson:"termsOfServiceAgreed"`
			Orders    string   `json:"orders"`
		}{
			Status:    account.Status,
			Contact:   account.Contact,
			AgreedTos: account.AgreedTos,
			Orders:    ordersUrl,
		}
		return c.JSON(acctReturn)
	}

	// get EAB from database
	eab, err := ctrler.acmeService.GetEabByKeyId(c.Context(), eabProtected.Kid)
	if err != nil {
		return ctrler.acmeProblem(c, acme_model.AccountDoesNotExist, "given External Account Binding key unknown:"+err.Error())
	}

	// ensure signature corresponds to store EAB
	err = checkEabSignature(eab, acctPayload)
	if err != nil {
		return ctrler.acmeProblem(c, acme_model.Unauthorized, "signature validation failed: "+err.Error())
	}

	// check whether kid belongs to account
	alignedContact := "mailto:" + eab.Contact
	if !slices.Contains(acctPayload.Contact, alignedContact) {
		return ctrler.acmeProblem(c, acme_model.Unauthorized, "contact contained in request does not match stored EAB")
	}

	// check whether inner and outer JWSs match
	outerJwk, err := util.ParseJwk(jwsParsed.KeyJson)
	if err != nil {
		return ctrler.acmeProblem(c, acme_model.ServerInternal, "unable to parse outer JWK: "+err.Error())
	}
	payloadBytes = make([]byte, base64.RawURLEncoding.DecodedLen(len(acctPayload.Eab.Payload)))
	_, err = base64.RawURLEncoding.Decode(payloadBytes, []byte(acctPayload.Eab.Payload))
	if err != nil {
		return ctrler.acmeProblem(c, acme_model.ServerInternal, "unable to decode inner payload: "+err.Error())
	}
	innerJwk, err := util.ParseJwk(string(payloadBytes))
	if err != nil {
		return ctrler.acmeProblem(c, acme_model.ServerInternal, "unable to parse inner JWK: "+err.Error())
	}

	if outerJwk.X != innerJwk.X {
		return ctrler.acmeProblem(c, acme_model.Unauthorized, "inner and outer JWK does not match")
	}

	acct := acme_model.Account{
		Status:            acme_model.ACCOUNT_VALID,
		CreatedAt:         time.Now().UTC().Format(time.RFC3339),
		Contact:           acctPayload.Contact,
		AgreedTos:         acctPayload.AgreedTos,
		AccountIdentifier: accountId,
		Jwk:               jwsParsed.KeyJson,
		Realm:             endpoint,
	}

	err = ctrler.acmeService.StoreAccount(c.Context(), acct)
	if err != nil {
		fiberlog.Error("unable to store account in database:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	ordersUrl, err := ctrler.newEndpointUrl(endpoint, ENDPOINT_ACCOUNT+"/order", accountId)

	if err != nil {
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// get new nonce for response
	nonce, err := ctrler.getNonceAndStore(c, endpoint)
	if err != nil {
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// prepare response
	c.Response().Header.Set("Content-Type", "application/json")
	c.Response().Header.Set("Location", acctUrl)
	c.Response().Header.Set("Replay-Nonce", nonce)
	c.Response().SetStatusCode(fiber.StatusCreated)

	actResponse := acme_model.AccountResponse{
		Status:    acme_model.ACCOUNT_VALID,
		Contact:   acct.Contact,
		OrdersUrl: ordersUrl,
	}

	resp, err := json.Marshal(actResponse)
	if err != nil {
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	return c.SendString(string(resp))
}

func (ctrler *AcmeController) UpdateAccount(c fiber.Ctx) error {
	c.Accepts("application/jose+json")

	endpoint := c.Params("endpoint")
	if _, ok := ctrler.config.AcmeConfig.Endpoints[endpoint]; !ok {
		return c.SendStatus(fiber.StatusNotFound)
	}

	accountId := c.Params("accountid")
	if accountId == "" {
		return ctrler.acmeProblem(c, acme_model.Malformed, "account id missing in url")
	}

	// verify JWS
	jws := c.Body()
	jwsParsed, err := util.ParseJwsHeader(string(jws))
	if err != nil {
		fiberlog.Warn("unable to parse JWS header:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	err = ctrler.verifyAndDeleteNonce(c, jwsParsed.Nonce)
	if err != nil {
		fiberlog.Warn("unable to verify or delete nonce:", err)
		return ctrler.acmeProblem(c, acme_model.BadNonce, err.Error())
	}

	// get account id from kid
	accountIdJws, err := ctrler.accountIdFromUrl(jwsParsed.Kid)
	if err != nil {
		fiberlog.Warn("unable to retrieve account id from url:", err)
		return ctrler.acmeProblem(c, acme_model.Malformed, "invalid account url in kid")
	}

	// get key for account id
	account, err := ctrler.acmeService.GetAccountById(c.Context(), accountIdJws)
	if err != nil {
		fiberlog.Warn("unable to retrieve account from database:", err)
		return ctrler.acmeProblem(c, acme_model.UnsupportedIdentifier, err.Error())
	}

	// verify JWS with key retrieved for account
	jwsVerified, err := util.VerifySignedMessage(string(jws), account.Jwk)
	if err != nil {
		fiberlog.Warn("unable to verify signed JWS:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// parse payload
	var acctPayload acme_model.AccountPayload
	err = json.Unmarshal(jwsVerified.Payload, &acctPayload)
	if err != nil {
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	var updates []acme_model.KeyValuePair

	if acctPayload.Contact != nil {
		// update contacts
		update := acme_model.KeyValuePair{
			Key:   "contact",
			Value: acctPayload.Contact,
		}
		updates = append(updates, update)
	} else if acctPayload.Status == acme_model.ACCOUNT_DEACTIVATED {
		// deactivate account
		account.Status = acme_model.ACCOUNT_DEACTIVATED
		update := acme_model.KeyValuePair{
			Key:   "status",
			Value: acme_model.ACCOUNT_DEACTIVATED,
		}
		updates = append(updates, update)
	}

	err = ctrler.acmeService.UpdateAccount(c.Context(), account.AccountIdentifier, updates)
	if err != nil {
		fiberlog.Error("unable to update account in database:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// if account was deactivated, also deactivate all authorizations for this account
	if acctPayload.Status == acme_model.ACCOUNT_DEACTIVATED {
		err = ctrler.acmeService.DeactivateAuthorizationByAccountId(c.Context(), account.AccountIdentifier)
		if err != nil {
			fiberlog.Error("unable to deactivate authorizations for deactivated account:", err)
			return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
		}
	}

	// get new nonce for response
	nonce, err := ctrler.getNonceAndStore(c, endpoint)
	if err != nil {
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// prepare response
	c.Response().Header.Set("Content-Type", "application/json")
	c.Response().Header.Set("Replay-Nonce", nonce)
	c.Response().SetStatusCode(fiber.StatusOK)

	actResponse := acme_model.AccountResponse{
		Status:  account.Status,
		Contact: account.Contact,
	}

	return c.JSON(actResponse)
}

func (ctrler *AcmeController) NewOrder(c fiber.Ctx) error {
	c.Accepts("application/jose+json")

	endpoint := c.Params("endpoint")
	if _, ok := ctrler.config.AcmeConfig.Endpoints[endpoint]; !ok {
		fiberlog.Warn("client requested endpoint not found:", endpoint)
		return c.SendStatus(fiber.StatusNotFound)
	}

	// verify JWS
	jws := c.Body()
	jwsParsed, err := util.ParseJwsHeader(string(jws))
	if err != nil {
		fiberlog.Warn("unable to parse JWS header:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// get account id from kid
	accountId, err := ctrler.accountIdFromUrl(jwsParsed.Kid)
	if err != nil {
		fiberlog.Warn("unable to retrieve account id from url:", err)
		return ctrler.acmeProblem(c, acme_model.Malformed, "invalid account url in kid")
	}

	// get key for account id
	account, err := ctrler.acmeService.GetAccountById(c.Context(), accountId)
	if err != nil {
		fiberlog.Warn("unable to retrieve account from database:", err)
		return ctrler.acmeProblem(c, acme_model.UnsupportedIdentifier, err.Error())
	}

	// check if account is in a good state
	if account.Status != acme_model.ACCOUNT_VALID {
		return ctrler.acmeProblem(c, acme_model.Unauthorized, "account is not valid")
	}

	// verify JWS with key retrieved for account
	_, err = util.VerifySignedMessage(string(jws), account.Jwk)
	if err != nil {
		fiberlog.Warn("unable to verify signed JWS:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// verify and delete nonce given by client
	err = ctrler.verifyAndDeleteNonce(c, jwsParsed.Nonce)
	if err != nil {
		fiberlog.Warn("unable to verify and delete nonce:", err)
		return ctrler.acmeProblem(c, acme_model.BadNonce, err.Error())
	}

	// parse payload
	var orderPayload acme_model.OrderPayload
	err = json.Unmarshal([]byte(jwsParsed.Payload), &orderPayload)
	if err != nil {
		fiberlog.Warn("failed to unmarshal payload:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// validate...
	// ...identifiers given
	if len(orderPayload.OrderIdentifiers) == 0 {
		return ctrler.acmeProblem(c, acme_model.Malformed, "no identifiers given")
	}
	// TODO: ...type of identifiers
	// ...
	// ... dates, if given
	if orderPayload.NotBefore != "" {
		if util.IsValid3339Date(orderPayload.NotBefore) != nil {
			return ctrler.acmeProblem(c, acme_model.Malformed, "notBefore date is not in valid RFC 3339 format")
		}
	}
	if orderPayload.NotAfter != "" {
		if util.IsValid3339Date(orderPayload.NotAfter) != nil {
			return ctrler.acmeProblem(c, acme_model.Malformed, "notAfter date is not in valid RFC 3339 format")
		}
	}

	// get new nonce for response
	nonce, err := ctrler.getNonceAndStore(c, endpoint)
	if err != nil {
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// prepare order reply details
	orderId := ctrler.acmeService.GetNewId()
	orderLocation, err := ctrler.newEndpointUrl(endpoint, ENDPOINT_ORDER, orderId)
	if err != nil {
		fiberlog.Warn("unable to construct order location url:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}
	orderExpiry := time.Now().UTC().Add(7 * 24 * time.Hour)
	authId := ctrler.acmeService.GetNewId()
	authUrl, err := ctrler.newEndpointUrl(endpoint, ENDPOINT_AUTHZ, authId)
	if err != nil {
		fiberlog.Warn("unable to construct authz url:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// construct order object
	order := acme_model.Order{
		OrderId:          orderId,
		AccountId:        accountId,
		Status:           acme_model.ORDER_PENDING,
		CreatedAt:        time.Now().UTC(),
		Expires:          orderExpiry,
		OrderIdentifiers: orderPayload.OrderIdentifiers,
		Authorizations:   []string{authUrl},
		Finalize:         orderLocation + "/finalize",
	}

	// add time to order object if given
	if notBefore, err := time.Parse(time.RFC3339, orderPayload.NotBefore); err != nil {
		order.NotBefore = notBefore
	}
	if notAfter, err := time.Parse(time.RFC3339, orderPayload.NotAfter); err != nil {
		order.NotAfter = notAfter
	}

	// write order to database
	err = ctrler.acmeService.StoreOrder(c.Context(), order)
	if err != nil {
		fiberlog.Error("unable to store order in database:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// construct auth object
	authObj := acme_model.Authorization{
		AuthId:     authId,
		Status:     acme_model.AUTHORIZATION_PENDING,
		CreatedAt:  time.Now().UTC(),
		ExpiresAt:  time.Now().UTC().Add(7 * 24 * time.Hour),
		OrderId:    orderId,
		AccountId:  accountId,
		Challenges: []acme_model.Challenge{},
	}
	err = ctrler.acmeService.StoreAuthorization(c.Context(), authObj)
	if err != nil {
		fiberlog.Error("unable to store authorization in database:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	c.Response().Header.Set("Location", orderLocation)
	c.Response().Header.Set("Replay-Nonce", nonce)
	c.Status(fiber.StatusCreated)

	orderResponse := struct {
		Status         string                       `json:"status"`
		Expires        string                       `json:"expires"`
		NotBefore      string                       `json:"notBefore,omitempty"`
		NotAfter       string                       `json:"notAfter,omitempty"`
		Identifiers    []acme_model.OrderIdentifier `json:"identifiers"`
		Authorizations []string                     `json:"authorizations"`
		Finalize       string                       `json:"finalize"`
	}{
		Status:         acme_model.ORDER_PENDING,
		Expires:        orderExpiry.Format(time.RFC3339),
		NotBefore:      orderPayload.NotBefore,
		NotAfter:       orderPayload.NotAfter,
		Identifiers:    orderPayload.OrderIdentifiers,
		Authorizations: []string{authUrl},
		Finalize:       orderLocation + "/finalize",
	}

	return c.JSON(orderResponse)
}

func (ctrler *AcmeController) prepareChallengeObject(endpoint string, authId string, accountIdentifier string, order acme_model.Order) ([]acme_model.Challenge, error) {
	var challenges []acme_model.Challenge
	for _, challengeType := range ctrler.config.AcmeConfig.Endpoints[endpoint].ChallengeTypes {
		challangeToken := ctrler.cryptoService.RandomStringB64(16)
		challengeId := ctrler.acmeService.GetNewId()
		expiresAt := time.Now().UTC().Add(7 * 24 * time.Hour)
		challengeUrl, err := ctrler.newEndpointUrl(endpoint, "challenge", challengeId)
		if err != nil {
			return []acme_model.Challenge{}, fmt.Errorf("unable to generate new challenge url: %w", err)
		}

		theType := ""
		switch challengeType {
		case acme_model.CHALLENGE_TYPE_HTTP01:
			theType = acme_model.CHALLENGE_TYPE_HTTP01
		case acme_model.CHALLENGE_TYPE_DNS01:
			theType = acme_model.CHALLENGE_TYPE_DNS01
		default:
			return []acme_model.Challenge{}, fmt.Errorf("unsupported challenge type configured: %s", challengeType)
		}

		challenge := acme_model.Challenge{
			ChallengeId: challengeId,
			AuthId:      authId,
			AccountId:   accountIdentifier,
			Status:      acme_model.CHALLENGE_PENDING,
			Type:        theType,
			Url:         challengeUrl,
			Token:       challangeToken,
			CreatedAt:   time.Now().UTC(),
			ExpiresAt:   expiresAt,
			Identifier:  order.OrderIdentifiers[0], // TODO: ensure to catch all identifiers given by client
		}
		challenges = append(challenges, challenge)
	}

	return challenges, nil
}

func (ctrler *AcmeController) Authorization(c fiber.Ctx) error {
	c.Accepts("application/jose+json")

	endpoint := c.Params("endpoint")
	if _, ok := ctrler.config.AcmeConfig.Endpoints[endpoint]; !ok {
		fiberlog.Warn("client requested endpoint not found:", endpoint)
		return c.SendStatus(fiber.StatusNotFound)
	}

	// verify JWS
	account, jws, err := ctrler.validateJws(c)
	if err != nil {
		fiberlog.Warn("unable to validate JWS:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	err = ctrler.verifyAndDeleteNonce(c, jws.Nonce)
	if err != nil {
		fiberlog.Warn("unable to validate JWS:", err)
		return ctrler.acmeProblem(c, acme_model.BadNonce, err.Error())
	}

	// validate url parameter
	authId := c.Params("authid")
	if authId == "" {
		fiberlog.Warn("client provided invalid auth id")
		return ctrler.acmeProblem(c, acme_model.Malformed, "authorization id missing in url")
	}

	// get authorization from database
	authorization, err := ctrler.acmeService.GetAuthorizationById(c.Context(), authId)
	if err != nil {
		fiberlog.Warn("unable to retrieve authorization from database:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// validate...
	//... whether authorization is still valid (not expired)
	if authorization.ExpiresAt.Before(time.Now().UTC()) {
		return ctrler.acmeProblem(c, acme_model.Malformed, "authorization has expired")
	}
	//... account of authorization matches account given in JWS
	if authorization.AccountId != account.AccountIdentifier {
		return ctrler.acmeProblem(c, acme_model.Unauthorized, "account id does not match authorization")
	}

	// get account id
	accountInfo, err := ctrler.acmeService.GetAccountById(c.Context(), account.AccountIdentifier)
	if err != nil {
		fiberlog.Warn("unable to retrieve account from database:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// reply nonce
	// nonce will be created up here to use it either for success response
	// or later in the auth confirm response
	nonce, err := ctrler.getNonceAndStore(c, endpoint)
	if err != nil {
		fiberlog.Error("unable to get or store nonce:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// check whether there is already a job for validating the challenge
	// if yes, perform validation of the corresponding challenge
	job, err := ctrler.dispatcherService.WorkerRepo.GetJobByExternalId(c.Context(), authorization.AuthId)
	if err == nil && (job.JobStatus == worker.JOB_STATUS_FINISHED || job.JobStatus == worker.JOB_STATUS_FAILED) { // a job was found, return to client
		challenge, err := ctrler.acmeService.GetChallengeByAuthorizationId(c.Context(), authorization.AuthId)
		if err != nil {
			e := fmt.Errorf("retrieving challenge from database failed: %w", err)
			fiberlog.Error(e)
			return ctrler.acmeProblem(c, acme_model.ServerInternal, e.Error())
		}

		var problemDetails acme_model.ProblemDetails
		authExpires := "" // set default auth expiry date to empty string

		switch job.JobStatus {
		case worker.JOB_STATUS_FINISHED:
			// below performs:
			// * challenge verification (finished/scucessful or failed)
			// * updates the authorization and challenge status according to the verification result
			err = ctrler.evalVerification(c, &authorization, &accountInfo, &challenge, job)
			if err != nil {
				fiberlog.Error(err.Error())
				return ctrler.acmeProblem(c, acme_model.ServerInternal, "there was an error evaluation the verification: "+err.Error())
			}

			if len(challenge.Error) > 0 {
				problemDetails = acme_model.ErrorWithTypeDetail(acme_model.IncorrectResponse, "verification failed: "+challenge.Error)
			}

			authExpires = authorization.ExpiresAt.Format(time.RFC3339)
		case worker.JOB_STATUS_FAILED:
			// job status is failed, so set the authorization
			err := ctrler.storeValidationError(c, &authorization, &challenge, "failure during verification: "+job.JobOutput)
			if err != nil {
				fiberlog.Error(err.Error())
			}

			// there should be already a challenge object for this auth, so update it with the error message
			err = ctrler.acmeService.UpdateAuthorizationUpsertChallenge(c.Context(), challenge.AuthId, challenge)
			if err != nil {
				fiberlog.Error("unable to update authorization with new challenge information:", err)
				return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
			}

			problemDetails = acme_model.ErrorWithTypeDetail(acme_model.IncorrectResponse, "verification failed: "+job.JobOutput)
		}

		// verification and authorization successful response
		c.Response().SetStatusCode(fiber.StatusOK)
		c.Response().Header.Set("Replay-Nonce", nonce)
		c.Response().Header.Set("Link", "<"+ctrler.config.HTTP.BaseUrl+"/directory>; rel=\"index\"")

		authResponse := struct {
			Status     string                         `json:"status"`
			Expires    string                         `json:"expires,omitempty,omitzero"`
			Identifier acme_model.OrderIdentifier     `json:"identifier"`
			Challenges []acme_model.ChallengeResponse `json:"challenges"`
		}{
			Status:  authorization.Status,
			Expires: authExpires,
			Identifier: acme_model.OrderIdentifier{
				Type:  challenge.Identifier.Type,
				Value: challenge.Identifier.Value,
			},
			Challenges: []acme_model.ChallengeResponse{
				{
					Type:      challenge.Type,
					Url:       challenge.Url,
					Status:    challenge.Status,
					Validated: challenge.Validated,
					Token:     challenge.Token,
					Error:     problemDetails,
				},
			},
		}
		return c.JSON(authResponse)
	}

	// get order from database
	order, err := ctrler.acmeService.GetOrderByAccountId(c.Context(), account.AccountIdentifier)
	if err != nil {
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// before creating new challenge check whether there already is one
	var filter []acme_model.KeyValuePair
	filter = append(filter, acme_model.KeyValuePair{
		Key:   "authId",
		Value: authId,
	})
	filter = append(filter, acme_model.KeyValuePair{
		Key:   "accountId",
		Value: authorization.AccountId,
	})
	var challenge acme_model.Challenge
	challenge, err = ctrler.acmeService.GetChallengeByFilter(c.Context(), filter)
	if err != nil {
		return ctrler.acmeProblem(c, acme_model.ServerInternal, "unable to check for existing challenge: "+err.Error())
	}

	var authExpires string
	var challengesResponse []acme_model.ChallengeResponse

	if len(challenge.ChallengeId) == 0 { // no challenge has been created yet
		// create challenge object(s)
		challenges, err := ctrler.prepareChallengeObject(endpoint, authId, account.AccountIdentifier, order)
		if err != nil {
			fiberlog.Error("unable to prepare challenge objects:", err)
			return ctrler.acmeProblem(c, acme_model.ServerInternal, "unable to prepare challenge object: "+err.Error())
		}

		// store challenge object(s) in database
		for _, challenge := range challenges {
			err = ctrler.acmeService.StoreChallenge(c.Context(), challenge)
			if err != nil {
				fiberlog.Error("unable to store challenge object in database:", err)
				return ctrler.acmeProblem(c, acme_model.ServerInternal, "unable to store challenge object: "+err.Error())
			}

			challengeResponse := acme_model.ChallengeResponse{
				Type:   challenge.Type,
				Url:    challenge.Url,
				Token:  challenge.Token,
				Status: challenge.Status,
			}
			challengesResponse = append(challengesResponse, challengeResponse)
		}

		authExpires = challenges[0].ExpiresAt.Format(time.RFC3339)
	} else {
		challengeResponse := acme_model.ChallengeResponse{
			Type:   challenge.Type,
			Url:    challenge.Url,
			Token:  challenge.Token,
			Status: challenge.Status,
		}
		challengesResponse = append(challengesResponse, challengeResponse)
		authExpires = challenge.ExpiresAt.Format(time.RFC3339)
	}

	// respond to client
	c.Response().SetStatusCode(fiber.StatusOK)
	c.Response().Header.Set("Replay-Nonce", nonce)
	c.Response().Header.Set("Link", "<"+ctrler.config.HTTP.BaseUrl+"/directory>; rel=\"index\"")

	authResponse := struct {
		Status     string                         `json:"status"`
		Expires    string                         `json:"expires"`
		Identifier acme_model.OrderIdentifier     `json:"identifier"`
		Challenges []acme_model.ChallengeResponse `json:"challenges"`
	}{
		Status:  acme_model.AUTHORIZATION_PENDING,
		Expires: authExpires,
		Identifier: acme_model.OrderIdentifier{
			Type:  order.OrderIdentifiers[0].Type,
			Value: order.OrderIdentifiers[0].Value,
		},
		Challenges: challengesResponse,
	}
	return c.JSON(authResponse)
}

func (ctrler *AcmeController) Challenge(c fiber.Ctx) error {
	c.Accepts("application/jose+json")

	endpoint := c.Params("endpoint")
	if _, ok := ctrler.config.AcmeConfig.Endpoints[endpoint]; !ok {
		fiberlog.Warn("client requested endpoint not found:", endpoint)
		return c.SendStatus(fiber.StatusNotFound)
	}

	challengeId := c.Params("challengeid")
	if challengeId == "" {
		fiberlog.Warn("client sent empty challengeid")
		return ctrler.acmeProblem(c, acme_model.Malformed, "error: empty challenge id")
	}

	// verify JWS
	_, jws, err := ctrler.validateJws(c)
	if err != nil {
		fiberlog.Warn("unable to validate JWS:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	err = ctrler.verifyAndDeleteNonce(c, jws.Nonce)
	if err != nil {
		fiberlog.Warn("unable to validate JWS:", err)
		return ctrler.acmeProblem(c, acme_model.BadNonce, err.Error())
	}

	if jws.Payload != "{}" {
		fiberlog.Warn("payload must be empty for this call")
		return ctrler.acmeProblem(c, acme_model.Malformed, "payload must be empty for this call")
	}

	// get challenge from database
	challenge, err := ctrler.acmeService.GetChallengeById(c.Context(), challengeId)
	if err != nil {
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// set challenge status to "processing"
	err = ctrler.updateChallengeStatus(c, challengeId, acme_model.CHALLENGE_PROCESSING, "")
	if err != nil {
		fiberlog.Error("unable to get or store nonce:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// check, is there already a challenge in this authorization, if yes, update it, otherwise create a new one
	err = ctrler.acmeService.UpdateAuthorizationUpsertChallenge(c.Context(), challenge.AuthId, challenge)
	if err != nil {
		fiberlog.Error("unable to check for existing challenge:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// reply nonce
	nonce, err := ctrler.getNonceAndStore(c, endpoint)
	if err != nil {
		fiberlog.Error("unable to get or store nonce:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// place job in the job queue depending on challenge type
	var job worker.Job

	switch challenge.Type {
	case acme_model.CHALLENGE_TYPE_HTTP01:
		jobInput := worker.JobValidateHttp01Input{
			Server: challenge.Identifier.Value,
			Token:  challenge.Token,
		}

		jobInputMarshalled, err := json.Marshal(jobInput)
		if err != nil {
			fiberlog.Error("unable to marhsal job input:", err)
			return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
		}

		job = worker.Job{
			JobType:    worker.JOB_TYPE_ACME_HTTP01VALIDATION,
			JobInput:   string(jobInputMarshalled),
			ExternalId: challenge.AuthId,
		}
	case acme_model.CHALLENGE_TYPE_DNS01:
		jobInput := worker.JobValidateDns01Input{
			DomainName:    challenge.Identifier.Value,
			Token:         challenge.Token,
			KeyThumbprint: "key", // TODO: get account key for challenge and add it to job input
		}

		jobInputMarshalled, err := json.Marshal(jobInput)
		if err != nil {
			fiberlog.Error("unable to marhsal job input:", err)
			return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
		}

		job = worker.Job{
			JobType:    worker.JOB_TYPE_ACME_NODNS01VALIDATION,
			JobInput:   string(jobInputMarshalled),
			ExternalId: challenge.AuthId,
		}
	default:
		fiberlog.Warn("unsupported challenge type:", challenge.Type)
		return ctrler.acmeProblem(c, acme_model.Malformed, "unsupported challenge type: "+challenge.Type)
	}

	jobId, err := ctrler.dispatcherService.SubmitJob(job)
	if err != nil {
		fiberlog.Error("unable to submit validation job:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// proceed with response to client
	authUrl, err := ctrler.newEndpointUrl(endpoint, ENDPOINT_AUTHZ, challenge.AuthId)
	if err != nil {
		fiberlog.Warn("unable to construct authz url:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	c.Response().SetStatusCode(fiber.StatusOK)
	c.Response().Header.Set("Replay-Nonce", nonce)
	c.Response().Header.Set("Link", "<"+authUrl+">;rel=\"up\"")
	c.Response().Header.Set("Location", challenge.Url)
	c.Response().Header.Set("Retry-After", "5")
	c.Response().Header.Set("rpcca-job-id", fmt.Sprintf("%d", jobId))

	challengeResponse := struct {
		Type   string `json:"type"`
		Url    string `json:"url"`
		Status string `json:"status"`
		Token  string `json:"token"`
	}{

		Type:   challenge.Type,
		Url:    challenge.Url,
		Status: acme_model.CHALLENGE_PENDING,
		Token:  challenge.Token,
	}

	return c.JSON(challengeResponse)
}

func (ctrler *AcmeController) ReturnOrders(c fiber.Ctx) error {
	c.Response().Header.Set("Content-Type", "application/json")
	c.Response().SetStatusCode(fiber.StatusOK)

	// Here you would typically return a list of orders for the account
	// For now, we just return a placeholder response
	return c.SendString(`{"orders": ["order1", "order2"]}`)
}

func (ctrler *AcmeController) ChallengeResponse(c fiber.Ctx) error {
	c.Response().SetStatusCode(fiber.StatusOK)
	return c.SendString("challenges")
}

func (ctrler *AcmeController) OrderStatus(c fiber.Ctx) error {
	c.Accepts("application/jose+json")

	endpoint := c.Params("endpoint")
	if _, ok := ctrler.config.AcmeConfig.Endpoints[endpoint]; !ok {
		fiberlog.Warn("client requested endpoint not found:", endpoint)
		return c.SendStatus(fiber.StatusNotFound)
	}

	orderId := c.Params("orderid")
	if orderId == "" {
		fiberlog.Warn("client sent empty order id:")
		return ctrler.acmeProblem(c, acme_model.Malformed, "order id empty")
	}

	// verify JWS
	jws := c.Body()
	jwsParsed, err := util.ParseJwsHeader(string(jws))
	if err != nil {
		fiberlog.Warn("unable to parse JWS header:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	err = ctrler.verifyAndDeleteNonce(c, jwsParsed.Nonce)
	if err != nil {
		fiberlog.Warn("unable to verify or delete nonce:", err)
		return ctrler.acmeProblem(c, acme_model.BadNonce, err.Error())
	}

	// get account id from kid
	accountId, err := ctrler.accountIdFromUrl(jwsParsed.Kid)
	if err != nil {
		fiberlog.Warn("unable to retrieve account id from url:", err)
		return ctrler.acmeProblem(c, acme_model.Malformed, "invalid account url in kid")
	}

	// get key for account id
	account, err := ctrler.acmeService.GetAccountById(c.Context(), accountId)
	if err != nil {
		fiberlog.Warn("unable to retrieve account from database:", err)
		return ctrler.acmeProblem(c, acme_model.UnsupportedIdentifier, err.Error())
	}

	// verify JWS with key retrieved for account
	_, err = util.VerifySignedMessage(string(jws), account.Jwk)
	if err != nil {
		fiberlog.Warn("unable to verify signed JWS:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// get order from database
	order, err := ctrler.acmeService.GetOrderById(c.Context(), orderId)
	if err != nil {
		fiberlog.Error("unable to get order by id:" + err.Error())
		return ctrler.acmeProblem(c, acme_model.Malformed, "unable to get order by id:"+err.Error())
	}

	// get job from database and check its status
	job, err := ctrler.dispatcherService.GetJobById(order.JobId)
	if err != nil {
		fiberlog.Error("unable to submit certificate request job:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	orderStatusOriginal := order.Status

	// translate job status into order status
	switch job.JobStatus {
	case worker.JOB_STATUS_QUEUED:
		order.Status = acme_model.ORDER_PROCESSING
	case worker.JOB_STATUS_FINISHED:
		order.Status = acme_model.ORDER_VALID
	case worker.JOB_STATUS_FAILED:
		order.Status = acme_model.ORDER_INVALID
	}

	// set order status according to job status
	certIssueError := acme_model.ProblemDetails{}
	if order.Status != orderStatusOriginal { // only update order status if required
		updates := make(map[string]string)
		updates["status"] = order.Status

		// extract certs from job output
		var jobCerts worker.JobIssueCertificateOutput
		err = json.Unmarshal([]byte(job.JobOutput), &jobCerts)
		if err != nil {
			fiberlog.Error("unable to unmarshal job output:", err)
			return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
		}

		// if order has status "valid" now, store certificate pem in order doc
		if order.Status == acme_model.ORDER_VALID {
			cert := acme_model.Certificate{
				CertId:          order.CertId,
				CertPem:         jobCerts.CertificatePem,
				CertChain:       jobCerts.CertificateChain,
				CertFingerprint: jobCerts.CertificateFingerprint,
				OrderId:         order.OrderId,
				AccountId:       account.AccountIdentifier,
			}
			err = ctrler.acmeService.StoreCertificate(c.Context(), cert)
			if err != nil {
				fiberlog.Error("unable to store certificate in database:", err)
				return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
			}
		}

		if order.Status == acme_model.ORDER_INVALID {
			certIssueError = acme_model.ProblemDetails{
				Type:   "urn:ietf:params:acme:error:badCSR",
				Detail: jobCerts.Detail,
			}
		}

		err = ctrler.acmeService.UpdateOrder(c.Context(), orderId, updates)
		if err != nil {
			fiberlog.Error("unable to update order status:", err)
			return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
		}
	}

	// reply nonce
	nonce, err := ctrler.getNonceAndStore(c, endpoint)
	if err != nil {
		fiberlog.Error("unable to get or store nonce:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// order location URL
	orderLocation, err := ctrler.newEndpointUrl(endpoint, ENDPOINT_ORDER, orderId)
	if err != nil {
		fiberlog.Error("unable to create order location URL:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, "unable to create order location URL: "+err.Error())
	}

	// certificate download URL
	certUrl, err := ctrler.newEndpointUrl(endpoint, "cert", order.CertId)
	if err != nil {
		fiberlog.Error("unable to create certificate download URL: " + err.Error())
		return ctrler.acmeProblem(c, acme_model.ServerInternal, "unable to create certificate download URL: "+err.Error())
	}

	c.Response().Header.Set("Replay-Nonce", nonce)
	c.Response().Header.Set("Link", "<"+ctrler.config.HTTP.BaseUrl+"/directory>; rel=\"index\"")
	c.Response().Header.Set("Location", orderLocation)
	c.Response().Header.Set("Retry-After", "20")

	c.Response().SetStatusCode(fiber.StatusOK)

	orderResponse := struct {
		Status         string                       `json:"status"`
		Expires        string                       `json:"expires"`
		NotBefore      string                       `json:"notBefore,omitempty"`
		NotAfter       string                       `json:"notAfter,omitempty"`
		Identifiers    []acme_model.OrderIdentifier `json:"identifiers"`
		Authorizations []string                     `json:"authorizations"`
		Finalize       string                       `json:"finalize"`
		Certificate    string                       `json:"certificate"`
		Error          acme_model.ProblemDetails    `json:"error,omitempty,omitzero"`
	}{
		Status:         order.Status,
		Expires:        order.Expires.Format(time.RFC3339),
		NotBefore:      order.NotBefore.Format(time.RFC3339),
		NotAfter:       order.NotAfter.Format(time.RFC3339),
		Identifiers:    order.OrderIdentifiers,
		Authorizations: order.Authorizations,
		Finalize:       orderLocation + "/finalize",
		Certificate:    certUrl,
		Error:          certIssueError,
	}
	return c.JSON(orderResponse)
}

func (ctrler *AcmeController) FinalizeOrder(c fiber.Ctx) error {
	c.Accepts("application/jose+json")

	endpoint := c.Params("endpoint")
	if _, ok := ctrler.config.AcmeConfig.Endpoints[endpoint]; !ok {
		fiberlog.Warn("client requested endpoint not found:", endpoint)
		return c.SendStatus(fiber.StatusNotFound)
	}

	orderId := c.Params("orderid")
	if orderId == "" {
		fiberlog.Warn("client sent empty order id")
		return ctrler.acmeProblem(c, acme_model.Malformed, "order id empty")
	}

	// verify JWS
	jws := c.Body()
	jwsParsed, err := util.ParseJwsHeader(string(jws))
	if err != nil {
		fiberlog.Warn("unable to parse JWS header:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	err = ctrler.verifyAndDeleteNonce(c, jwsParsed.Nonce)
	if err != nil {
		fiberlog.Warn("unable to verify or delete nonce:", err)
		return ctrler.acmeProblem(c, acme_model.BadNonce, err.Error())
	}

	// get account id from kid
	accountId, err := ctrler.accountIdFromUrl(jwsParsed.Kid)
	if err != nil {
		fiberlog.Warn("unable to retrieve account id from url:", err)
		return ctrler.acmeProblem(c, acme_model.Malformed, "invalid account url in kid")
	}

	// get key for account id
	account, err := ctrler.acmeService.GetAccountById(c.Context(), accountId)
	if err != nil {
		fiberlog.Warn("unable to retrieve account from database:", err)
		return ctrler.acmeProblem(c, acme_model.UnsupportedIdentifier, err.Error())
	}

	// check if account is in a good state
	if account.Status != acme_model.ACCOUNT_VALID {
		return ctrler.acmeProblem(c, acme_model.Unauthorized, "account is not valid")
	}

	// verify JWS with key retrieved for account
	verifiedParsed, err := util.VerifySignedMessage(string(jws), account.Jwk)
	if err != nil {
		fiberlog.Warn("unable to verify signed JWS:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// get order from database
	order, err := ctrler.acmeService.GetOrderById(c.Context(), orderId)
	if err != nil {
		fiberlog.Error("unable to get order by id:" + err.Error())
		return ctrler.acmeProblem(c, acme_model.Malformed, "unable to get order by id:"+err.Error())
	}

	// check if order is in ready status
	if order.Status != acme_model.ORDER_READY {
		fiberlog.Warn("order not ready")
		return ctrler.acmeProblem(c, acme_model.OrderNotReady, "order is not in ready state")
	}

	// check whether the given order belongs to the given account
	if order.AccountId != account.AccountIdentifier {
		fiberlog.Warn("account does not own the order")
		return ctrler.acmeProblem(c, acme_model.Malformed, "given account does not own the order")
	}

	// check expiry date of the order
	if order.Expires.Before(time.Now().UTC()) {
		fiberlog.Warn("order expired")
		return ctrler.acmeProblem(c, acme_model.Malformed, "given order expired already")
	}

	// check CSR
	var rawCsr acme_model.CsrPayload
	err = json.Unmarshal(verifiedParsed.Payload, &rawCsr)
	if err != nil {
		fiberlog.Warn("CSR given not valid: " + err.Error())
		return ctrler.acmeProblem(c, acme_model.Malformed, "CSR provided is not valid: "+err.Error())
	}

	csrRaw, err := base64.RawURLEncoding.DecodeString(rawCsr.Csr)
	if err != nil {
		fiberlog.Warn("unable to decode CSR from base64: " + err.Error())
		return ctrler.acmeProblem(c, acme_model.Malformed, "unable to decode CSR from base64: "+err.Error())
	}

	csr, err := x509.ParseCertificateRequest(csrRaw)
	if err != nil {
		fiberlog.Warn("unable to parse CSR: " + err.Error())
		return ctrler.acmeProblem(c, acme_model.Malformed, "CSR provided cannot be parsed: "+err.Error())
	}

	// do some checks of the incoming CSR
	if len(order.OrderIdentifiers) != len(csr.DNSNames) {
		fiberlog.Warn("amount of requested names do not match amount of identifiers")
		return ctrler.acmeProblem(c, acme_model.BadCSRError, "amount of requested names do not match amount of identifiers")
	}

	for _, dns := range order.OrderIdentifiers {
		if !slices.Contains(csr.DNSNames, dns.Value) {
			fiberlog.Warn("requested dns name not found in validated identifier(s)")
			return ctrler.acmeProblem(c, acme_model.BadCSRError, "requested dns name not found in validated identifier(s)")
		}
	}

	// populate SANs struct
	var csrSans []certservice.CertificateSan
	for _, san := range csr.DNSNames {
		csrSans = append(csrSans, certservice.CertificateSan{
			SanType:  "DNS",
			SanValue: san,
		})
	}

	certRequest := certservice.CertificateRequest{
		CaName:       ctrler.config.AcmeConfig.Endpoints[endpoint].CaName,
		Csr:          base64.StdEncoding.EncodeToString(csrRaw),
		Sans:         csrSans,
		TemplateName: ctrler.config.AcmeConfig.Endpoints[endpoint].Template,
		RequestId:    orderId,
		Requestor:    "acme_" + order.AccountId,
		Metadata: map[string]string{
			"acme_account":  account.AccountIdentifier,
			"acme_contacts": strings.Join(account.Contact, ","),
			"acme_realm":    account.Realm,
			"acme_order":    order.OrderId,
		},
	}

	// TODO: check if identifiers are in valid state

	// TODO: check if extensions in the CSR are fine

	// check if there is a certificate with these details
	cert, err := ctrler.certService.HasAccountCert(c.Context(), account, certRequest)
	if err != nil {
		fiberlog.Error("unable to query for certificate: " + err.Error())
		return ctrler.acmeProblem(c, acme_model.ServerInternal, "unable to query for existing certificates: "+err.Error())
	}
	if len(cert.CertFingerprint) != 0 {
		// there is a certificate present with the details provided by the CSR, check renewal window
		isRenewalDue, err := util.IsRenewalDue(ctrler.config.AcmeConfig.Limits.RenewalStart, cert.NotAfter)
		if err != nil {
			fiberlog.Error("there was an error calculating renewal window: " + err.Error())
			return ctrler.acmeProblem(c, acme_model.ServerInternal, "there was an error calculating renewal window: "+err.Error())
		}

		if !isRenewalDue {
			// outside of renewal window, return error
			return ctrler.acmeProblem(c, acme_model.BadCSRError, "a certificate with these details is already present, revoke first.")
		}
	}

	// construct certificate URL
	certId := ctrler.acmeService.GetNewId()
	certUrl, err := ctrler.newEndpointUrl(endpoint, "cert", certId)
	if err != nil {
		fiberlog.Error("unable to create certificate download URL: " + err.Error())
		return ctrler.acmeProblem(c, acme_model.ServerInternal, "unable to create certificate download URL: "+err.Error())
	}

	// update order with relevant data
	orderUpdates := make(map[string]string, 3)
	orderUpdates["csr"] = rawCsr.Csr
	orderUpdates["certId"] = certId
	orderUpdates["status"] = acme_model.ORDER_PROCESSING

	err = ctrler.acmeService.UpdateOrder(c.Context(), orderId, orderUpdates)
	if err != nil {
		fiberlog.Error("unable to order: ", err.Error())
		return ctrler.acmeProblem(c, acme_model.ServerInternal, "unable to update order: "+err.Error())
	}

	// place certificate creation job in the queue
	jobInput := worker.JobIssueCertificateInput{
		CertificateRequest: certRequest,
	}

	jobInputMarshalled, err := json.Marshal(jobInput)
	if err != nil {
		fiberlog.Error("unable to marshal job input:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	job := worker.Job{
		JobType:    worker.JOB_TYPE_CERT_REQUEST,
		JobInput:   string(jobInputMarshalled),
		ExternalId: certId,
	}

	jobId, err := ctrler.dispatcherService.SubmitJob(job)
	if err != nil {
		fiberlog.Error("unable to submit certificate request job:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// set order's job id
	err = ctrler.acmeService.UpdateOrderWithJobId(c.Context(), orderId, jobId)
	if err != nil {
		fiberlog.Error("unable to set job id:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// reply nonce
	nonce, err := ctrler.getNonceAndStore(c, endpoint)
	if err != nil {
		fiberlog.Error("unable to get or store nonce:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// order location URL
	orderLocation, err := ctrler.newEndpointUrl(endpoint, ENDPOINT_ORDER, orderId)
	if err != nil {
		fiberlog.Error("unable to create order location URL:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, "unable to create order location URL: "+err.Error())
	}

	c.Response().Header.Set("Replay-Nonce", nonce)
	c.Response().Header.Set("Link", "<"+ctrler.config.HTTP.BaseUrl+"/directory>; rel=\"index\"")
	c.Response().Header.Set("Location", orderLocation)
	c.Response().Header.Set("Retry-After", "20")
	c.Response().Header.Set("rpcca-job-id", fmt.Sprintf("%d", jobId))

	c.Response().SetStatusCode(fiber.StatusOK)

	orderResponse := struct {
		Status         string                       `json:"status"`
		Expires        string                       `json:"expires"`
		NotBefore      string                       `json:"notBefore,omitempty"`
		NotAfter       string                       `json:"notAfter,omitempty"`
		Identifiers    []acme_model.OrderIdentifier `json:"identifiers"`
		Authorizations []string                     `json:"authorizations"`
		Finalize       string                       `json:"finalize"`
		Certificate    string                       `json:"certificate"`
	}{
		Status:         acme_model.ORDER_PROCESSING,
		Expires:        order.Expires.Format(time.RFC3339),
		NotBefore:      order.NotBefore.Format(time.RFC3339),
		NotAfter:       order.NotAfter.Format(time.RFC3339),
		Identifiers:    order.OrderIdentifiers,
		Authorizations: order.Authorizations,
		Finalize:       orderLocation + "/finalize",
		Certificate:    certUrl,
	}
	return c.JSON(orderResponse)
}

func (ctrler *AcmeController) ReturnCert(c fiber.Ctx) error {
	c.Accepts("application/jose+json")

	endpoint := c.Params("endpoint")
	if _, ok := ctrler.config.AcmeConfig.Endpoints[endpoint]; !ok {
		fiberlog.Warn("client requested endpoint not found:", endpoint)
		return c.SendStatus(fiber.StatusNotFound)
	}

	certId := c.Params("certid")
	if certId == "" {
		fiberlog.Warn("client sent empty certificate id")
		return ctrler.acmeProblem(c, acme_model.Malformed, "certificate id empty")
	}

	// verify JWS
	jws := c.Body()
	jwsParsed, err := util.ParseJwsHeader(string(jws))
	if err != nil {
		fiberlog.Warn("unable to parse JWS header:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	err = ctrler.verifyAndDeleteNonce(c, jwsParsed.Nonce)
	if err != nil {
		fiberlog.Warn("unable to verify or delete nonce:", err)
		return ctrler.acmeProblem(c, acme_model.BadNonce, err.Error())
	}

	// get account id from kid
	accountId, err := ctrler.accountIdFromUrl(jwsParsed.Kid)
	if err != nil {
		fiberlog.Warn("unable to retrieve account id from url:", err)
		return ctrler.acmeProblem(c, acme_model.Malformed, "invalid account url in kid")
	}

	// get key for account id
	account, err := ctrler.acmeService.GetAccountById(c.Context(), accountId)
	if err != nil {
		fiberlog.Warn("unable to retrieve account from database:", err)
		return ctrler.acmeProblem(c, acme_model.UnsupportedIdentifier, err.Error())
	}

	// check if account is in a good state
	if account.Status != acme_model.ACCOUNT_VALID {
		return ctrler.acmeProblem(c, acme_model.Unauthorized, "account is not valid")
	}

	// verify JWS with key retrieved for account
	_, err = util.VerifySignedMessage(string(jws), account.Jwk)
	if err != nil {
		fiberlog.Warn("unable to verify signed JWS:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// get certificate from database
	filter := make(map[string]string, 2)
	filter["certificateId"] = certId
	filter["accountId"] = account.AccountIdentifier

	cert, err := ctrler.acmeService.GetCertificateByFilter(c.Context(), filter)
	if err != nil {
		fiberlog.Error("unable to get certificate:" + err.Error())
		return ctrler.acmeProblem(c, acme_model.ServerInternal, "unable to get certificate by id:"+err.Error())
	}

	certResponse := cert.CertPem + cert.CertChain + "\n" // adding a newline to make Certbot accept the response

	// reply nonce
	nonce, err := ctrler.getNonceAndStore(c, endpoint)
	if err != nil {
		fiberlog.Error("unable to get or store nonce:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	c.Response().SetStatusCode(fiber.StatusOK)
	c.Response().Header.Set("Replay-Nonce", nonce)
	c.Response().Header.Set("Content-Type", "application/pem-certificate-chain")
	c.Response().Header.Set("Link", "<"+ctrler.config.HTTP.BaseUrl+"/directory>; rel=\"index\"")

	return c.SendString(certResponse)
}

func (ctrler *AcmeController) RevokeCert(c fiber.Ctx) error {
	c.Accepts("application/jose+json")

	endpoint := c.Params("endpoint")
	if _, ok := ctrler.config.AcmeConfig.Endpoints[endpoint]; !ok {
		fiberlog.Warn("client requested endpoint not found:", endpoint)
		return c.SendStatus(fiber.StatusNotFound)
	}

	// verify JWS
	jws := c.Body()
	jwsParsed, err := util.ParseJwsHeader(string(jws))
	if err != nil {
		fiberlog.Warn("unable to parse JWS header:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	// check which verification to use...
	// ...acount's key
	// get account id from kid
	if jwsParsed.Kid != "" {
		accountId, err := ctrler.accountIdFromUrl(jwsParsed.Kid)
		if err != nil {
			fiberlog.Warn("unable to retrieve account id from url:", err)
			return ctrler.acmeProblem(c, acme_model.Malformed, "invalid account url in kid")
		}

		// get key for account id
		account, err := ctrler.acmeService.GetAccountById(c.Context(), accountId)
		if err != nil {
			fiberlog.Warn("unable to retrieve account from database:", err)
			return ctrler.acmeProblem(c, acme_model.UnsupportedIdentifier, err.Error())
		}

		// check if account is in a good state
		if account.Status != acme_model.ACCOUNT_VALID {
			return ctrler.acmeProblem(c, acme_model.Unauthorized, "account is not valid")
		}

		// verify JWS with key retrieved for account
		_, err = util.VerifySignedMessage(string(jws), account.Jwk)
		if err != nil {
			fiberlog.Warn("unable to verify signed JWS:", err)
			return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
		}

		var revokePayload acme_model.CertificateRevokePayload
		err = json.Unmarshal([]byte(jwsParsed.Payload), &revokePayload)
		if err != nil {
			return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
		}

		// try parse certificate from payload
		certRaw, err := base64.RawURLEncoding.DecodeString(revokePayload.Certificate)
		if err != nil {
			fiberlog.Warn("unable to decode certificate from base64: " + err.Error())
			return ctrler.acmeProblem(c, acme_model.Malformed, "unable to decode certificate from base64: "+err.Error())
		}

		certFp := util.CalculateCertFingerprintByByte(certRaw)
		filter := make(map[string]string)
		filter["cert_metadata.acme_account"] = accountId

		jobInput := worker.JobRevokeCertificateInput{
			CaName:      ctrler.config.AcmeConfig.Endpoints[endpoint].CaName,
			Fingerprint: certFp,
			Reason:      "superseded",
			Filter:      filter,
			OrFilter:    make(map[string][]string),
		}

		jobInputMarshalled, err := json.Marshal(jobInput)
		if err != nil {
			fiberlog.Error("unable to marshal job input:", err)
			return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
		}

		job := worker.Job{
			JobType:    worker.JOB_TYPE_CERT_REVOKE,
			JobInput:   string(jobInputMarshalled),
			ExternalId: accountId,
			Done:       make(chan struct{}),
		}

		jobId, err := ctrler.dispatcherService.SubmitJob(job)
		if err != nil {
			fiberlog.Error("unable to submit certificate request job:", err)
			return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
		}

		// here, wait for the job to be finished as clients expects a result of the revocation
		<-job.Done

		jobResult, err := ctrler.dispatcherService.GetJobById(jobId)
		if err != nil {
			fiberlog.Error("unable to get job by id:", err)
			return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
		}

		if jobResult.JobStatus != worker.JOB_STATUS_FINISHED {
			e := fmt.Errorf("revocation job failed with: %s", jobResult.JobOutput)
			fiberlog.Error(e)
			return ctrler.acmeProblem(c, acme_model.ServerInternal, e.Error())
		}
	} else if jwsParsed.Jwk != "" {
		// ...or certificate's key
		// parse and unmarshal payload
		// parse payload
		fiberlog.Debug("using certificate to verify revoke request")
		var revokePayload acme_model.CertificateRevokePayload
		err = json.Unmarshal([]byte(jwsParsed.Payload), &revokePayload)
		if err != nil {
			return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
		}

		// try parse certificate from payload
		certRaw, err := base64.RawURLEncoding.DecodeString(revokePayload.Certificate)
		if err != nil {
			fiberlog.Warn("unable to decode certificate from base64: " + err.Error())
			return ctrler.acmeProblem(c, acme_model.Malformed, "unable to decode certificate from base64: "+err.Error())
		}
		cert, err := x509.ParseCertificate(certRaw)
		if err != nil {
			fiberlog.Warn("unable to parse CSR: " + err.Error())
			return ctrler.acmeProblem(c, acme_model.Malformed, "certificate provided cannot be parsed: "+err.Error())
		}

		block, _ := pem.Decode(cert.Raw)
		if block == nil {
			fiberlog.Error("unable to decode certificate to PEM")
			return ctrler.acmeProblem(c, acme_model.ServerInternal, "unable to decode certificate to PEM")
		}

		certFp := util.CalculateCertFingerprint(block)
		fiberlog.Debug("certificate fingerprint calculated:", certFp)
	}

	// get certificate by account id

	err = ctrler.verifyAndDeleteNonce(c, jwsParsed.Nonce)
	if err != nil {
		fiberlog.Warn("unable to verify or delete nonce:", err)
		return ctrler.acmeProblem(c, acme_model.BadNonce, err.Error())
	}

	// reply nonce
	nonce, err := ctrler.getNonceAndStore(c, endpoint)
	if err != nil {
		fiberlog.Error("unable to get or store nonce:", err)
		return ctrler.acmeProblem(c, acme_model.ServerInternal, err.Error())
	}

	c.Response().SetStatusCode(fiber.StatusOK)
	c.Response().Header.Set("Replay-Nonce", nonce)
	c.Response().Header.Set("Link", "<"+ctrler.config.HTTP.BaseUrl+"/directory>; rel=\"index\"")

	return c.Send([]byte{})
}

func (ctrler *AcmeController) acmeProblem(c fiber.Ctx, acmeError acme_model.AcmeError, details string) error {
	c.Response().Header.Set("Content-Type", "application/problem+json")

	var statusCode int

	switch acmeError {
	case acme_model.BadNonce:
		statusCode = fiber.StatusBadRequest
	case acme_model.Unauthorized:
		statusCode = fiber.StatusUnauthorized
	default:
		statusCode = fiber.StatusBadRequest
	}

	c.Response().SetStatusCode(statusCode)
	return c.JSON(acmeError.Error(statusCode, details))
}

func (ctrler *AcmeController) getNonceAndStore(c fiber.Ctx, endpoint string) (string, error) {
	nonce := ctrler.cryptoService.RandomStringB64(8)
	if nonce == "" {
		return "", errors.New("no nonce generated")
	}

	err := ctrler.acmeService.StoreNonce(c.Context(), nonce, endpoint)
	if err != nil {
		return "", errors.New("error storing nonce: " + err.Error())
	}
	return nonce, nil
}

func (ctrler *AcmeController) verifyAndDeleteNonce(c fiber.Ctx, nonceStr string) error {
	nonce, err := ctrler.acmeService.GetAndDeleteNonce(c.Context(), nonceStr)
	if err != nil {
		return errors.New("error retrieving nonce: " + err.Error())
	}

	if nonce.Nonce == "" {
		return errors.New("nonce not found")
	}

	return nil
}

func (ctrler *AcmeController) validateJws(c fiber.Ctx) (acme_model.Account, util.JwsParsed, error) {
	var account acme_model.Account

	// verify JWS
	jws := c.Body()
	jwsParsed, err := util.ParseJwsHeader(string(jws))
	if err != nil {
		return acme_model.Account{}, util.JwsParsed{}, err
	}

	// get account id from kid
	accountId, err := ctrler.accountIdFromUrl(jwsParsed.Kid)
	if err != nil {
		return acme_model.Account{}, jwsParsed, err
	}

	// get key for account id
	account, err = ctrler.acmeService.GetAccountById(c.Context(), accountId)
	if err != nil {
		return acme_model.Account{}, jwsParsed, err
	}

	// verify JWS with key retrieved for account
	_, err = util.VerifySignedMessage(string(jws), account.Jwk)
	if err != nil {
		return acme_model.Account{}, jwsParsed, err
	}

	return account, jwsParsed, nil
}

// creates a new URL for the given realm, endpoint and id
func (ctrler *AcmeController) newEndpointUrl(realm string, endpoint string, id string) (string, error) {
	if realm == "" || endpoint == "" || id == "" {
		return "", errors.New("realm, endpoint and id must be set")
	}

	basePath := ctrler.config.HTTP.BaseUrl + "/acme/" + realm

	return basePath + "/" + endpoint + "/" + id, nil
}

func (ctrler *AcmeController) accountIdFromUrl(url string) (string, error) {
	// get the account id from the url like below
	// <base-path>/acme/main/account/<account-id>

	n := strings.LastIndex(url, "/")
	if n == -1 {
		return "", errors.New("no / found in url")
	}

	id := url[n+1:]

	if id == "" {
		return "", errors.New("no account id found in url")
	}

	return id, nil
}

// based on the token and thumbprint (SHA256) of the key
// compute the key authorization.
// from RFC8555:
// base64url(sha256(token || '.' || base64url(Thumbprint(accountKey))))
func computeKeyAuthorizationHash(token string, keyThumb string) string {
	keyAuth := token + "." + keyThumb
	h := sha256.New()
	h.Write([]byte(keyAuth))
	hSum := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(hSum)
}

func (ctrler *AcmeController) challengeHttp01Verification(token string, account *acme_model.Account, clientResponse string) error {
	// just check basic format of the response
	tmp := strings.Split(clientResponse, ".")
	if len(tmp) != 2 {
		return errors.New("key authorization format retrieved from client is invalid")
	}

	// compute key authorization
	keyThumb, err := util.GetKeyThumbprint(account.Jwk, crypto.SHA256)
	if err != nil {
		return errors.New("unable to compute key thumbprint: " + err.Error())
	}
	keyAuthHash := token + "." + keyThumb

	if clientResponse != keyAuthHash {
		fiberlog.Debugf("verification failed. client's key auth vs. stored key auth: %s - %s", clientResponse, keyAuthHash)
		return fmt.Errorf("key authorizaton provided by the client does not match stored key authorization")
	}

	return nil
}

func (ctrler *AcmeController) challengeDns01Verification(token string, account *acme_model.Account, clientResponse string) error {
	// compare challenge provided by the client with the value looked up in the TXT record
	keyThumb, err := util.GetKeyThumbprint(account.Jwk, crypto.SHA256)
	if err != nil {
		return errors.New("unable to compute key thumbprint: " + err.Error())
	}

	// compute key authorization
	keyAuthHash := computeKeyAuthorizationHash(token, keyThumb)

	// compare with client response
	var txtRecords worker.JobValidateDns01Output
	err = json.Unmarshal([]byte(clientResponse), &txtRecords)
	if err != nil {
		return errors.New("unable to parse client response for dns-01 challenge: " + err.Error())
	}

	if !slices.Contains(txtRecords.TxtRecords, keyAuthHash) {
		return errors.New("key authorization hash not found in TXT records provided by client")
	}

	return nil
}

func (ctrler *AcmeController) evalVerification(c fiber.Ctx, auth *acme_model.Authorization, account *acme_model.Account, challenge *acme_model.Challenge, job worker.Job) error {
	if challenge.Type == acme_model.CHALLENGE_TYPE_HTTP01 {
		err := ctrler.challengeHttp01Verification(challenge.Token, account, job.JobOutput)
		if err != nil { // http verification failed
			return ctrler.storeValidationError(c, auth, challenge, "http-01 verification failed: "+err.Error())
		}
		return ctrler.storeValidationSuccess(c, auth, challenge)
	}

	if challenge.Type == acme_model.CHALLENGE_TYPE_DNS01 {
		switch job.JobType {
		case worker.JOB_TYPE_ACME_DNS01VALIDATION:
			err := ctrler.challengeDns01Verification(challenge.Token, account, job.JobOutput)
			if err != nil { // dns verification failed
				prob := acme_model.ErrorWithTypeDetail(acme_model.IncorrectResponse, "dns-01 verification failed: "+err.Error())
				probJson, err := json.Marshal(prob)
				if err != nil {
					return errors.New("unable to marshal problem details: " + err.Error())
				}
				return ctrler.storeValidationError(c, auth, challenge, string(probJson))
			}
			return ctrler.storeValidationSuccess(c, auth, challenge)
		case worker.JOB_TYPE_ACME_NODNS01VALIDATION:
			if job.JobOutput == "{\"status\": \"ok\"}" {
				return ctrler.storeValidationSuccess(c, auth, challenge)
			}
			return ctrler.storeValidationError(c, auth, challenge, "no-dns verification failed: "+job.JobOutput)
		}
	}
	return nil
}

func (ctrler *AcmeController) storeValidationSuccess(c fiber.Ctx, auth *acme_model.Authorization, challenge *acme_model.Challenge) error {
	auth.Status = acme_model.AUTHORIZATION_VALID
	challenge.Status = acme_model.CHALLENGE_VALID
	challenge.Validated = time.Now().UTC()

	err := ctrler.updateAuthorizationStatus(c, auth.AuthId, auth.Status)
	if err != nil {
		return errors.New("unable to update authorization doc with new status: " + err.Error())
	}

	err = ctrler.acmeService.UpdateAuthorizationModifyChallenge(c.Context(), auth.AuthId, "status", challenge.Status)
	if err != nil {
		return errors.New("unable to update authorization doc with new challenge status: " + err.Error())
	}

	err = ctrler.acmeService.UpdateAuthorizationModifyChallenge(c.Context(), auth.AuthId, "validated", challenge.Validated)
	if err != nil {
		return errors.New("unable to update authorization doc with new challenge validated time: " + err.Error())
	}

	err = ctrler.updateChallengeStatus(c, challenge.ChallengeId, challenge.Status, "")
	if err != nil {
		return errors.New("unable to update challenge doc with new status: " + err.Error())
	}

	err = ctrler.acmeService.UpdateOrderStatus(c.Context(), auth.OrderId, acme_model.ORDER_READY)
	if err != nil {
		return errors.New("unable to update order doc with new status: " + err.Error())
	}

	return nil
}

func (ctrler *AcmeController) storeValidationError(c fiber.Ctx, auth *acme_model.Authorization, challenge *acme_model.Challenge, errMsg string) error {
	challenge.Status = acme_model.CHALLENGE_INVALID
	auth.Status = acme_model.AUTHORIZATION_INVALID

	err := ctrler.updateChallengeStatus(c, challenge.ChallengeId, challenge.Status, errMsg)
	if err != nil {
		e := fmt.Errorf("failed updating challenge status: %w", err)
		fiberlog.Error(e)
		return e
	}

	err = ctrler.updateAuthorizationStatus(c, auth.AuthId, auth.Status)
	if err != nil {
		return errors.New("unable to update authorization doc with failed validation status: " + err.Error())
	}

	return nil
}

func (ctrler *AcmeController) updateChallengeStatus(c fiber.Ctx, challengeId string, status string, errMsg string) error {
	kv := []acme_model.KeyValuePair{
		{
			Key:   "status",
			Value: status,
		},
		{
			Key:   "validated",
			Value: time.Now().UTC(),
		},
	}

	// if we are supposed to change to "validated"
	// add a timestamp as well
	if status == acme_model.CHALLENGE_VALID {
		validated := acme_model.KeyValuePair{
			Key:   "validated",
			Value: time.Now().UTC(),
		}
		kv = append(kv, validated)
	}

	// if we are supposed to change the status to error
	// add an error message as well
	if status == acme_model.CHALLENGE_INVALID {
		validated := acme_model.KeyValuePair{
			Key:   "error",
			Value: errMsg,
		}
		kv = append(kv, validated)
	}

	return ctrler.acmeService.UpdateChallenge(c.Context(), challengeId, kv)
}

func (ctrler *AcmeController) updateAuthorizationStatus(c fiber.Ctx, authId string, status string) error {
	kv := []acme_model.KeyValuePair{
		{
			Key:   "status",
			Value: status,
		},
	}

	return ctrler.acmeService.UpdateAuthorization(c.Context(), authId, kv)
}

func checkEabSignature(eab acme_model.AcmeEAB, accountPayload acme_model.AccountPayload) error {
	// base64 decode stored MAC
	decodedMac := make([]byte, base64.RawURLEncoding.DecodedLen(len(eab.Mac)))
	_, err := base64.RawURLEncoding.Decode(decodedMac, []byte(eab.Mac))
	if err != nil {
		return fmt.Errorf("unable to base64 decode MAC: %w", err)
	}

	// create HMAC of payload sent
	// IMPORTANT: by default SHA256 is suggested, so this is hard-coded here
	signature := hmac.New(sha256.New, decodedMac)
	signature.Write([]byte(accountPayload.Eab.Protected + "." + accountPayload.Eab.Payload))
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature.Sum(nil))

	// compare HMAC sent by the client with the one computed above
	if signatureB64 != accountPayload.Eab.Signature {
		return fmt.Errorf("signature of MAC sent does not match signature of MAC stored")
	}

	return nil
}
