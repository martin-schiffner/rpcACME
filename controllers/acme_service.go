package controllers

import (
	"context"
	acme_model "rpcca/acme/models"
	"rpcca/acme/util"
	"time"

	"github.com/oklog/ulid/v2"
)

type AcmeService interface {
	// nonces
	StoreNonce(ctx context.Context, nonce string, realm string) error
	GetAndDeleteNonce(ctx context.Context, nonceStr string) (acme_model.Nonce, error)

	// accounts
	GetAccountById(ctx context.Context, accountId string) (acme_model.Account, error)
	GetAccountByContact(ctx context.Context, contact string) (acme_model.Account, error)
	CheckAccountPresence(ctx context.Context, contact string) (bool, error)
	StoreAccount(ctx context.Context, account acme_model.Account) error
	UpdateAccount(ctx context.Context, accountId string, updates []acme_model.KeyValuePair) error

	// orders
	GetOrderById(ctx context.Context, orderId string) (acme_model.Order, error)
	GetOrderByAccountId(ctx context.Context, accountId string) (acme_model.Order, error)
	StoreOrder(ctx context.Context, order acme_model.Order) error
	UpdateOrder(ctx context.Context, orderId string, updates map[string]string) error
	UpdateOrderStatus(ctx context.Context, orderId, status string) error
	UpdateOrderWithCsr(ctx context.Context, orderId, csr string) error
	UpdateOrderWithCertLink(ctx context.Context, orderId, certLink string) error
	UpdateOrderWithJobId(ctx context.Context, orderId string, jobId int64) error

	// authorizations
	GetAuthorizationById(ctx context.Context, authId string) (acme_model.Authorization, error)
	GetAuthorizationByAccountId(ctx context.Context, accountId string) (acme_model.Authorization, error)
	GetChallengeByFilter(ctx context.Context, filter []acme_model.KeyValuePair) (acme_model.Challenge, error)
	StoreAuthorization(ctx context.Context, auth acme_model.Authorization) error
	UpdateAuthorization(ctx context.Context, authId string, updates []acme_model.KeyValuePair) error
	UpdateAuthorizationAddChallenge(ctx context.Context, authId string, challenge acme_model.Challenge) error
	UpdateAuthorizationModifyChallenge(ctx context.Context, authId string, key string, valueNew any) error
	UpdateAuthorizationUpsertChallenge(ctx context.Context, authId string, challenge acme_model.Challenge) error
	DeactivateAuthorizationByAccountId(ctx context.Context, accountId string) error
	HasAuthorizationChallenge(ctx context.Context, authId string, challengeId string) (bool, error)

	// challenges
	GetChallengeById(ctx context.Context, challengeId string) (acme_model.Challenge, error)
	GetChallengeByAuthorizationId(ctx context.Context, authId string) (acme_model.Challenge, error)
	StoreChallenge(ctx context.Context, challenge acme_model.Challenge) error
	UpdateChallenge(ctx context.Context, challengeId string, updates []acme_model.KeyValuePair) error

	// certificate
	GetCertificateById(ctx context.Context, certId string) (acme_model.Certificate, error)
	GetCertificateByFilter(ctx context.Context, filter map[string]string) (acme_model.Certificate, error)
	StoreCertificate(ctx context.Context, cert acme_model.Certificate) error

	// external account binding
	GetEabByContact(ctx context.Context, contact string) (acme_model.AcmeEAB, error)
	GetEabByKeyId(ctx context.Context, keyId string) (acme_model.AcmeEAB, error)
	StoreEab(ctx context.Context, eab acme_model.AcmeEAB) error
	UpdateEab(ctx context.Context, eab acme_model.AcmeEAB) error

	// helpers
	GetNewId() string
	GetNewEab(contact string) (acme_model.AcmeEAB, error)
}

type acmeService struct {
	acmeRepository acme_model.AcmeRepository
	cryptoService  CryptoService
}

func NewAcmeService(ar acme_model.AcmeRepository, cs CryptoService) AcmeService {
	return &acmeService{
		acmeRepository: ar,
		cryptoService:  cs,
	}
}

// ******************************
// nonces
// ******************************
func (s *acmeService) StoreNonce(ctx context.Context, nonce string, realm string) error {
	err := s.acmeRepository.StoreNonce(ctx, nonce, realm)
	if err != nil {
		return err
	}
	return nil
}

func (s *acmeService) GetAndDeleteNonce(ctx context.Context, nonceStr string) (acme_model.Nonce, error) {
	nonce, err := s.acmeRepository.GetAndDeleteNonce(ctx, nonceStr)
	if err != nil {
		return acme_model.Nonce{}, err
	}
	return nonce, nil
}

// ******************************
// accounts
// ******************************
func (s *acmeService) GetAccountById(ctx context.Context, accountId string) (acme_model.Account, error) {
	account, err := s.acmeRepository.GetAccountById(ctx, accountId)
	if err != nil {
		return acme_model.Account{}, err
	}
	return account, nil
}

func (s *acmeService) GetAccountByContact(ctx context.Context, contact string) (acme_model.Account, error) {
	account, err := s.acmeRepository.GetAccountByContact(ctx, contact)
	if err != nil {
		return acme_model.Account{}, err
	}
	return account, nil
}

func (s *acmeService) CheckAccountPresence(ctx context.Context, contact string) (bool, error) {
	return s.acmeRepository.CheckAccountByContact(ctx, contact)
}

func (s *acmeService) StoreAccount(ctx context.Context, account acme_model.Account) error {
	err := s.acmeRepository.StoreAccount(ctx, account)
	if err != nil {
		return err
	}
	return nil
}

func (s *acmeService) UpdateAccount(ctx context.Context, accountId string, updates []acme_model.KeyValuePair) error {
	return s.acmeRepository.UpdateAccount(ctx, accountId, updates)
}

// ******************************
// orders
// ******************************
func (s *acmeService) GetOrderById(ctx context.Context, orderId string) (acme_model.Order, error) {
	order, err := s.acmeRepository.GetOrderById(ctx, orderId)
	if err != nil {
		return acme_model.Order{}, err
	}
	return order, nil
}

func (s *acmeService) GetOrderByAccountId(ctx context.Context, accountId string) (acme_model.Order, error) {
	order, err := s.acmeRepository.GetOrderByAccountId(ctx, accountId)
	if err != nil {
		return acme_model.Order{}, err
	}
	return order, nil
}

func (s *acmeService) StoreOrder(ctx context.Context, order acme_model.Order) error {
	err := s.acmeRepository.StoreOrder(ctx, order)
	if err != nil {
		return err
	}
	return nil
}

func (s *acmeService) UpdateOrder(ctx context.Context, orderId string, updates map[string]string) error {
	kv := make([]acme_model.KeyValuePair, 0, len(updates))
	for k, v := range updates {
		kv = append(kv, acme_model.KeyValuePair{
			Key:   k,
			Value: v,
		})
	}

	err := s.acmeRepository.UpdateOrder(ctx, orderId, kv)
	if err != nil {
		return err
	}

	return nil
}

func (s *acmeService) UpdateOrderStatus(ctx context.Context, orderId string, status string) error {
	kv := []acme_model.KeyValuePair{
		{
			Key:   "status",
			Value: status,
		},
		{
			Key:   "updatedAt",
			Value: time.Now().UTC(),
		},
	}

	err := s.acmeRepository.UpdateOrder(ctx, orderId, kv)
	if err != nil {
		return err
	}

	return nil
}

func (s *acmeService) UpdateOrderWithCsr(ctx context.Context, orderId, csr string) error {
	kv := []acme_model.KeyValuePair{
		{
			Key:   "csr",
			Value: csr,
		},
		{
			Key:   "updatedAt",
			Value: time.Now().UTC(),
		},
	}

	err := s.acmeRepository.UpdateOrder(ctx, orderId, kv)
	if err != nil {
		return err
	}

	return nil
}

func (s *acmeService) UpdateOrderWithCertLink(ctx context.Context, orderId, certLink string) error {
	kv := []acme_model.KeyValuePair{
		{
			Key:   "cert",
			Value: certLink,
		},
		{
			Key:   "updatedAt",
			Value: time.Now().UTC(),
		},
	}

	err := s.acmeRepository.UpdateOrder(ctx, orderId, kv)
	if err != nil {
		return err
	}

	return nil
}

func (s *acmeService) UpdateOrderWithJobId(ctx context.Context, orderId string, jobId int64) error {
	kv := []acme_model.KeyValuePair{
		{
			Key:   "jobId",
			Value: jobId,
		},
		{
			Key:   "updatedAt",
			Value: time.Now().UTC(),
		},
	}

	err := s.acmeRepository.UpdateOrder(ctx, orderId, kv)
	if err != nil {
		return err
	}

	return nil
}

// ******************************
// authorizations
// ******************************
func (s *acmeService) GetAuthorizationById(ctx context.Context, authId string) (acme_model.Authorization, error) {
	auth, err := s.acmeRepository.GetAuthorizationById(ctx, authId)
	if err != nil {
		return acme_model.Authorization{}, err
	}
	return auth, nil
}

func (s *acmeService) GetAuthorizationByAccountId(ctx context.Context, accountId string) (acme_model.Authorization, error) {
	auth, err := s.acmeRepository.GetAuthorizationByAccountId(ctx, accountId)
	if err != nil {
		return acme_model.Authorization{}, err
	}
	return auth, nil
}

func (s *acmeService) StoreAuthorization(ctx context.Context, auth acme_model.Authorization) error {
	err := s.acmeRepository.StoreAuthorization(ctx, auth)
	if err != nil {
		return err
	}
	return nil
}

func (s *acmeService) UpdateAuthorization(ctx context.Context, authId string, updates []acme_model.KeyValuePair) error {
	err := s.acmeRepository.UpdateAuthorization(ctx, authId, updates)
	if err != nil {
		return err
	}
	return nil
}

func (s *acmeService) UpdateAuthorizationAddChallenge(ctx context.Context, authId string, challenge acme_model.Challenge) error {
	err := s.acmeRepository.UpdateAuthorizationAddChallenge(ctx, authId, challenge)
	if err != nil {
		return err
	}
	return nil
}

func (s *acmeService) UpdateAuthorizationModifyChallenge(ctx context.Context, authId string, key string, valueNew any) error {
	err := s.acmeRepository.UpdateAuthorizationModifyChallenge(ctx, authId, key, valueNew)
	if err != nil {
		return err
	}
	return nil
}

func (s *acmeService) UpdateAuthorizationUpsertChallenge(ctx context.Context, authId string, challenge acme_model.Challenge) error {
	return s.acmeRepository.UpdateAuthorizationUpsertChallenge(ctx, authId, challenge)
}

func (s *acmeService) DeactivateAuthorizationByAccountId(ctx context.Context, accountId string) error {
	return s.acmeRepository.UpdateAuthorizationStatusByAccountId(ctx, accountId, acme_model.AUTHORIZATION_DEACTIVATED)
}

func (s *acmeService) HasAuthorizationChallenge(ctx context.Context, authId string, challengeId string) (bool, error) {
	return s.acmeRepository.HasAuthorizationChallenge(ctx, authId, challengeId)
}

// ******************************
// challenges
// ******************************
func (s *acmeService) GetChallengeById(ctx context.Context, challengeId string) (acme_model.Challenge, error) {
	challenge, err := s.acmeRepository.GetChallengeById(ctx, challengeId)
	if err != nil {
		return acme_model.Challenge{}, err
	}
	return challenge, nil
}

func (s *acmeService) GetChallengeByAuthorizationId(ctx context.Context, authId string) (acme_model.Challenge, error) {
	challenge, err := s.acmeRepository.GetChallengeByAuthorizationId(ctx, authId)
	if err != nil {
		return acme_model.Challenge{}, err
	}
	return challenge, nil
}

func (s *acmeService) GetChallengeByFilter(ctx context.Context, filter []acme_model.KeyValuePair) (acme_model.Challenge, error) {
	challenge, err := s.acmeRepository.GetChallengeByFilter(ctx, filter)
	if err != nil {
		return acme_model.Challenge{}, err
	}
	return challenge, nil
}

func (s *acmeService) StoreChallenge(ctx context.Context, challenge acme_model.Challenge) error {
	err := s.acmeRepository.StoreChallenge(ctx, challenge)
	if err != nil {
		return err
	}
	return nil
}

func (s *acmeService) UpdateChallenge(ctx context.Context, challengeId string, updates []acme_model.KeyValuePair) error {
	err := s.acmeRepository.UpdateChallenge(ctx, challengeId, updates)
	if err != nil {
		return err
	}
	return nil
}

func (s *acmeService) GetCertificateById(ctx context.Context, certId string) (acme_model.Certificate, error) {
	return s.acmeRepository.GetCertificateById(ctx, certId)
}

func (s *acmeService) GetCertificateByFilter(ctx context.Context, filter map[string]string) (acme_model.Certificate, error) {
	return s.acmeRepository.GetCertificate(ctx, filter)
}

func (s *acmeService) StoreCertificate(ctx context.Context, certificate acme_model.Certificate) error {
	return s.acmeRepository.StoreCertificate(ctx, certificate)
}

// external account binding
func (s *acmeService) GetEabByContact(ctx context.Context, contact string) (acme_model.AcmeEAB, error) {
	return s.acmeRepository.GetEabByContact(ctx, contact)
}

func (s *acmeService) GetEabByKeyId(ctx context.Context, keyId string) (acme_model.AcmeEAB, error) {
	return s.acmeRepository.GetEabByKeyId(ctx, keyId)
}

func (s *acmeService) StoreEab(ctx context.Context, eab acme_model.AcmeEAB) error {
	return s.acmeRepository.StoreEab(ctx, eab)
}

func (s *acmeService) UpdateEab(ctx context.Context, eab acme_model.AcmeEAB) error {
	return s.acmeRepository.UpdateEab(ctx, eab)
}

// helpers
func (s *acmeService) GetNewId() string {
	return ulid.Make().String()
}

func (s *acmeService) GetNewEab(contact string) (acme_model.AcmeEAB, error) {
	err := util.IsValidEmail(contact)
	if err != nil {
		return acme_model.AcmeEAB{}, err
	}

	mac := s.cryptoService.RandomStringB64(32)
	return acme_model.AcmeEAB{
		KeyId:     s.GetNewId(),
		Mac:       mac,
		CreatedAt: time.Now().UTC(),
		Contact:   contact,
	}, nil
}
