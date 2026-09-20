package models

import (
	"context"
	"errors"

	"time"

	fiberlog "github.com/gofiber/fiber/v3/log"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const (
	CollectionNonces         = "acme_nonces"
	CollectionAccounts       = "acme_accounts"
	CollectionOrders         = "acme_orders"
	CollectionAuthorizations = "acme_authorizations"
	CollectionChallenges     = "acme_challenges"
	CollctionCertificates    = "acme_certificates"
	CollectionEab            = "acme_eab"
)

type KeyValuePair struct {
	Key   string
	Value any
}

type mongoRepository struct {
	mongoInstance *MongoInstance
}

type AcmeRepository interface {
	// nonces
	GetAndDeleteNonce(ctx context.Context, nonceStr string) (Nonce, error)
	StoreNonce(ctx context.Context, nonce string, realm string) error

	// accounts
	GetAccountById(ctx context.Context, accountId string) (Account, error)
	GetAccountByContact(ctx context.Context, contact string) (Account, error)
	CheckAccountByContact(ctx context.Context, contact string) (bool, error)
	StoreAccount(ctx context.Context, account Account) error
	UpdateAccount(ctx context.Context, accountId string, updates []KeyValuePair) error

	// orders
	GetOrderById(ctx context.Context, orderId string) (Order, error)
	GetOrderByAccountId(ctx context.Context, accountId string) (Order, error)
	StoreOrder(ctx context.Context, order Order) error
	UpdateOrder(ctx context.Context, orderId string, updates []KeyValuePair) error

	// authorizations
	GetAuthorizationById(ctx context.Context, authId string) (Authorization, error)
	GetAuthorizationByAccountId(ctx context.Context, accountId string) (Authorization, error)
	StoreAuthorization(ctx context.Context, auth Authorization) error
	UpdateAuthorization(ctx context.Context, authId string, updates []KeyValuePair) error
	UpdateAuthorizationAddChallenge(ctx context.Context, authId string, challenge Challenge) error
	UpdateAuthorizationModifyChallenge(ctx context.Context, authId string, key string, valueNew any) error
	UpdateAuthorizationUpsertChallenge(ctx context.Context, authId string, challenge Challenge) error
	UpdateAuthorizationStatusByAccountId(ctx context.Context, accountId string, status string) error
	HasAuthorizationChallenge(ctx context.Context, authId string, challengeId string) (bool, error)

	// challanges
	GetChallengeById(ctx context.Context, challengeId string) (Challenge, error)
	GetChallengeByAuthorizationId(ctx context.Context, authId string) (Challenge, error)
	GetChallengeByFilter(ctx context.Context, filter []KeyValuePair) (Challenge, error)
	StoreChallenge(ctx context.Context, challange Challenge) error
	UpdateChallenge(ctx context.Context, challengeId string, updates []KeyValuePair) error

	// certificate
	GetCertificateById(ctx context.Context, certId string) (Certificate, error)
	GetCertificate(ctx context.Context, filter map[string]string) (Certificate, error)
	StoreCertificate(ctx context.Context, cert Certificate) error

	// External Account Binding (EAB)
	GetEabByContact(ctx context.Context, contact string) (AcmeEAB, error)
	GetEabByKeyId(ctx context.Context, keyId string) (AcmeEAB, error)
	StoreEab(ctx context.Context, eab AcmeEAB) error
	UpdateEab(ctx context.Context, eab AcmeEAB) error
}

func NewAcmeRepository(mongoInstance *MongoInstance) AcmeRepository {
	return &mongoRepository{
		mongoInstance: mongoInstance,
	}
}

// ******************************
// nonces
// ******************************
func (m *mongoRepository) StoreNonce(ctx context.Context, nonce string, realm string) error {
	coll := m.mongoInstance.Db.Collection(CollectionNonces)
	nonceDoc := Nonce{
		Nonce:     nonce,
		Realm:     realm,
		Reserved:  true,
		CreatedAt: time.Now().UTC(),
	}

	_, err := coll.InsertOne(ctx, nonceDoc)
	if err != nil {
		fiberlog.Error("error storing ACME nonce: ", err)
		return err
	}
	return nil
}

func (m *mongoRepository) GetAndDeleteNonce(ctx context.Context, nonceStr string) (Nonce, error) {
	coll := m.mongoInstance.Db.Collection(CollectionNonces)

	var nonce Nonce
	err := coll.FindOneAndDelete(ctx, bson.D{{Key: "nonce", Value: nonceStr}}).Decode(&nonce)
	if err != nil {
		return Nonce{}, err
	}
	return nonce, nil
}

// ******************************
// accounts
// ******************************
func (m *mongoRepository) GetAccountById(ctx context.Context, accountId string) (Account, error) {
	coll := m.mongoInstance.Db.Collection(CollectionAccounts)

	var account Account
	err := coll.FindOne(ctx, bson.D{{Key: "accountIdentifier", Value: accountId}}).Decode(&account)
	if err != nil {
		return Account{}, err
	}
	return account, nil
}

func (m *mongoRepository) GetAccountByContact(ctx context.Context, contact string) (Account, error) {
	coll := m.mongoInstance.Db.Collection(CollectionAccounts)

	var account Account
	opts := options.FindOne().SetSort(bson.D{{Key: "createdAt", Value: -1}})
	err := coll.FindOne(ctx, bson.D{{Key: "contact", Value: contact}, {Key: "status", Value: "valid"}}, opts).Decode(&account)
	if err != nil {
		return Account{}, err
	}
	return account, nil
}

// checks whether an account is know to the system
// doesn't care about the account status (valid, deactivated,...)
func (m *mongoRepository) CheckAccountByContact(ctx context.Context, contact string) (bool, error) {
	coll := m.mongoInstance.Db.Collection(CollectionAccounts)

	opts := options.FindOne().SetSort(bson.D{{Key: "createdAt", Value: -1}})
	res := coll.FindOne(ctx, bson.D{{Key: "contact", Value: contact}}, opts)
	err := res.Err()
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (m *mongoRepository) StoreAccount(ctx context.Context, account Account) error {
	coll := m.mongoInstance.Db.Collection("acme_accounts")

	_, err := coll.InsertOne(ctx, account)
	if err != nil {
		return err
	}
	return nil
}

func (m *mongoRepository) UpdateAccount(ctx context.Context, accountId string, updates []KeyValuePair) error {
	coll := m.mongoInstance.Db.Collection(CollectionAccounts)

	d := bson.D{}
	for _, update := range updates {
		e := bson.E{
			Key:   update.Key,
			Value: update.Value,
		}
		d = append(d, e)
	}

	_, err := coll.UpdateOne(ctx, bson.D{{Key: "accountIdentifier", Value: accountId}}, bson.M{"$set": d})
	if err != nil {
		return err
	}
	return nil
}

// orders
func (m *mongoRepository) GetOrderById(ctx context.Context, orderId string) (Order, error) {
	coll := m.mongoInstance.Db.Collection(CollectionOrders)

	var order Order
	err := coll.FindOne(ctx, bson.D{{Key: "orderId", Value: orderId}}).Decode(&order)
	if err != nil {
		return Order{}, err
	}

	return order, nil
}

func (m *mongoRepository) GetOrderByAccountId(ctx context.Context, accountId string) (Order, error) {
	coll := m.mongoInstance.Db.Collection(CollectionOrders)

	var order Order
	err := coll.FindOne(ctx, bson.D{{Key: "accountId", Value: accountId}}).Decode(&order)
	if err != nil {
		return Order{}, err
	}
	return order, nil
}

func (m *mongoRepository) StoreOrder(ctx context.Context, order Order) error {
	coll := m.mongoInstance.Db.Collection(CollectionOrders)

	_, err := coll.InsertOne(ctx, order)

	if err != nil {
		return err
	}
	return nil
}

func (m *mongoRepository) UpdateOrder(ctx context.Context, orderId string, updates []KeyValuePair) error {
	coll := m.mongoInstance.Db.Collection(CollectionOrders)

	d := bson.D{}
	for _, update := range updates {
		e := bson.E{
			Key:   update.Key,
			Value: update.Value,
		}
		d = append(d, e)
	}

	_, err := coll.UpdateOne(ctx, bson.D{{Key: "orderId", Value: orderId}}, bson.M{"$set": d})
	if err != nil {
		return err
	}
	return nil
}

// authorizations
func (m *mongoRepository) GetAuthorizationById(ctx context.Context, authId string) (Authorization, error) {
	coll := m.mongoInstance.Db.Collection(CollectionAuthorizations)

	var auth Authorization
	err := coll.FindOne(ctx, bson.D{{Key: "authId", Value: authId}}).Decode(&auth)
	if err != nil {
		return Authorization{}, err
	}
	return auth, nil
}

func (m *mongoRepository) GetAuthorizationByAccountId(ctx context.Context, accountId string) (Authorization, error) {
	coll := m.mongoInstance.Db.Collection(CollectionAuthorizations)

	var auth Authorization
	err := coll.FindOne(ctx, bson.D{{Key: "accountId", Value: accountId}}).Decode(&auth)
	if err != nil {
		return Authorization{}, err
	}
	return auth, nil
}

func (m *mongoRepository) StoreAuthorization(ctx context.Context, auth Authorization) error {
	coll := m.mongoInstance.Db.Collection(CollectionAuthorizations)

	_, err := coll.InsertOne(ctx, auth)
	if err != nil {
		return err
	}
	return nil
}

func (m *mongoRepository) UpdateAuthorization(ctx context.Context, authId string, updates []KeyValuePair) error {
	coll := m.mongoInstance.Db.Collection(CollectionAuthorizations)

	d := bson.D{}
	for _, update := range updates {
		e := bson.E{
			Key:   update.Key,
			Value: update.Value,
		}
		d = append(d, e)
	}

	_, err := coll.UpdateOne(ctx, bson.D{{Key: "authId", Value: authId}}, bson.M{"$set": d})
	if err != nil {
		return err
	}
	return nil
}

func (m *mongoRepository) UpdateAuthorizationAddChallenge(ctx context.Context, authId string, challenge Challenge) error {
	coll := m.mongoInstance.Db.Collection(CollectionAuthorizations)

	b := bson.M{
		"$push": bson.M{
			"challenges": bson.M{
				"challengeId": challenge.ChallengeId,
				"type":        challenge.Type,
				"url":         challenge.Url,
				"status":      challenge.Status,
				"validated":   challenge.Validated,
				"error":       challenge.Error,
			},
		},
	}
	_, err := coll.UpdateOne(ctx, bson.D{{Key: "authId", Value: authId}}, b)
	if err != nil {
		return err
	}

	return nil
}

func (m *mongoRepository) UpdateAuthorizationModifyChallenge(ctx context.Context, authId string, key string, valueNew any) error {
	coll := m.mongoInstance.Db.Collection(CollectionAuthorizations)

	identifier := bson.D{
		bson.E{
			Key:   "authId",
			Value: authId,
		},
	}

	update := bson.M{
		"$set": bson.M{
			"challenges.$[]." + key: valueNew,
		},
	}

	_, err := coll.UpdateOne(ctx, identifier, update)
	if err != nil {
		return err
	}

	return nil
}

func (m *mongoRepository) UpdateAuthorizationUpsertChallenge(ctx context.Context, authId string, challenge Challenge) error {
	coll := m.mongoInstance.Db.Collection(CollectionAuthorizations)

	filter := bson.D{{Key: "authId", Value: authId}}

	newChallenge := bson.M{
		"challengeId": challenge.ChallengeId,
		"type":        challenge.Type,
		"url":         challenge.Url,
		"status":      challenge.Status,
		"validated":   challenge.Validated,
		"error":       challenge.Error,
	}

	pipeline := mongo.Pipeline{
		bson.D{{Key: "$set", Value: bson.M{
			"challenges": bson.M{
				"$cond": bson.M{
					"if": bson.M{
						"$in": bson.A{
							challenge.ChallengeId,
							bson.M{"$ifNull": bson.A{"$challenges.challengeId", bson.A{}}},
						},
					},
					// in case the challenge already exists, we update it
					"then": bson.M{
						"$map": bson.M{
							"input": "$challenges",
							"as":    "c",
							"in": bson.M{
								"$cond": bson.M{
									"if":   bson.M{"$eq": bson.A{"$$c.challengeId", challenge.ChallengeId}},
									"then": newChallenge,
									"else": "$$c",
								},
							},
						},
					},
					// in case the challenge does not exist yet -> append
					"else": bson.M{
						"$concatArrays": bson.A{
							bson.M{"$ifNull": bson.A{"$challenges", bson.A{}}},
							bson.A{newChallenge},
						},
					},
				},
			},
		}}},
	}

	opts := options.UpdateOne().SetUpsert(true)
	_, err := coll.UpdateOne(ctx, filter, pipeline, opts)
	if err != nil {
		return err
	}
	return nil
}

func (m *mongoRepository) UpdateAuthorizationStatusByAccountId(ctx context.Context, accountId string, status string) error {
	coll := m.mongoInstance.Db.Collection(CollectionAuthorizations)

	identifier := bson.D{
		bson.E{
			Key:   "accountId",
			Value: accountId,
		},
	}

	update := bson.M{
		"$set": bson.M{
			"status": status,
		},
	}

	_, err := coll.UpdateMany(ctx, identifier, update)
	if err != nil {
		return err
	}
	return nil
}

func (m *mongoRepository) HasAuthorizationChallenge(ctx context.Context, authId string, challengeId string) (bool, error) {
	coll := m.mongoInstance.Db.Collection(CollectionAuthorizations)

	var auth Authorization
	err := coll.FindOne(ctx, bson.D{{Key: "authId", Value: authId}, {Key: "challenges.challengeId", Value: challengeId}}).Decode(&auth)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			fiberlog.Debug("no doc")
			return false, nil
		}
		fiberlog.Debug("other error")
		return false, err
	}

	if len(auth.Challenges) == 0 {
		fiberlog.Debug(auth)
		fiberlog.Debug("challenges empty")
		return false, nil
	}
	fiberlog.Debug("found")
	return true, nil
}

// ******************************
// challanges
// ******************************
func (m *mongoRepository) GetChallengeById(ctx context.Context, challengeId string) (Challenge, error) {
	coll := m.mongoInstance.Db.Collection(CollectionChallenges)

	var challenge Challenge
	err := coll.FindOne(ctx, bson.D{{Key: "challengeId", Value: challengeId}}).Decode(&challenge)
	if err != nil {
		return Challenge{}, err
	}
	return challenge, nil
}

func (m *mongoRepository) GetChallengeByAuthorizationId(ctx context.Context, authId string) (Challenge, error) {
	coll := m.mongoInstance.Db.Collection(CollectionChallenges)

	var challenge Challenge
	err := coll.FindOne(ctx, bson.D{{Key: "authId", Value: authId}}).Decode(&challenge)
	if err != nil {
		return Challenge{}, err
	}
	return challenge, nil
}

func (m *mongoRepository) GetChallengeByFilter(ctx context.Context, filter []KeyValuePair) (Challenge, error) {
	coll := m.mongoInstance.Db.Collection(CollectionChallenges)

	d := bson.D{}
	for _, update := range filter {
		e := bson.E{
			Key:   update.Key,
			Value: update.Value,
		}
		d = append(d, e)
	}

	var challenge Challenge
	err := coll.FindOne(ctx, d).Decode(&challenge)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return Challenge{}, nil
		}
		return Challenge{}, err
	}
	return challenge, nil
}

func (m *mongoRepository) StoreChallenge(ctx context.Context, challange Challenge) error {
	coll := m.mongoInstance.Db.Collection(CollectionChallenges)

	_, err := coll.InsertOne(ctx, challange)
	if err != nil {
		return err
	}
	return nil
}

func (m *mongoRepository) UpdateChallenge(ctx context.Context, challengeId string, updates []KeyValuePair) error {
	coll := m.mongoInstance.Db.Collection(CollectionChallenges)

	d := bson.D{}
	for _, update := range updates {
		e := bson.E{
			Key:   update.Key,
			Value: update.Value,
		}
		d = append(d, e)
	}

	_, err := coll.UpdateOne(ctx, bson.D{{Key: "challengeId", Value: challengeId}}, bson.M{"$set": d})
	if err != nil {
		return err
	}
	return nil
}

func (m *mongoRepository) GetCertificateById(ctx context.Context, certId string) (Certificate, error) {
	coll := m.mongoInstance.Db.Collection(CollctionCertificates)

	var certificate Certificate
	err := coll.FindOne(ctx, bson.D{{Key: "certId", Value: certId}}).Decode(&certificate)
	if err != nil {
		return Certificate{}, err
	}

	return certificate, nil
}

func (m *mongoRepository) GetCertificate(ctx context.Context, filter map[string]string) (Certificate, error) {
	coll := m.mongoInstance.Db.Collection(CollctionCertificates)

	d := bson.D{}
	for k, v := range filter {
		e := bson.E{
			Key:   k,
			Value: v,
		}
		d = append(d, e)
	}

	var certificate Certificate
	err := coll.FindOne(ctx, d).Decode(&certificate)
	if err != nil {
		return Certificate{}, err
	}

	return certificate, nil
}

func (m *mongoRepository) StoreCertificate(ctx context.Context, certificate Certificate) error {
	coll := m.mongoInstance.Db.Collection(CollctionCertificates)

	certificate.CreatedAt = time.Now().UTC()

	_, err := coll.InsertOne(ctx, certificate)
	if err != nil {
		return err
	}
	return nil
}

// ******************************
// External Account Bindings
// ******************************

func (m *mongoRepository) GetEabByContact(ctx context.Context, contact string) (AcmeEAB, error) {
	coll := m.mongoInstance.Db.Collection(CollectionEab)

	var eab AcmeEAB
	err := coll.FindOne(ctx, bson.D{{Key: "contact", Value: contact}}).Decode(&eab)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return AcmeEAB{}, nil
		}
		return AcmeEAB{}, err
	}

	return eab, nil
}

func (m *mongoRepository) GetEabByKeyId(ctx context.Context, keyId string) (AcmeEAB, error) {
	coll := m.mongoInstance.Db.Collection(CollectionEab)

	var eab AcmeEAB
	err := coll.FindOne(ctx, bson.D{{Key: "keyId", Value: keyId}}).Decode(&eab)
	if err != nil {
		return AcmeEAB{}, err
	}

	return eab, nil
}

func (m *mongoRepository) StoreEab(ctx context.Context, eab AcmeEAB) error {
	coll := m.mongoInstance.Db.Collection(CollectionEab)
	_, err := coll.InsertOne(ctx, eab)
	if err != nil {
		return err
	}
	return nil
}

func (m *mongoRepository) UpdateEab(ctx context.Context, eab AcmeEAB) error {
	coll := m.mongoInstance.Db.Collection(CollectionEab)

	b := bson.M{
		"$set": bson.M{
			"updatedOn": time.Now().UTC(),
			"keyId":     eab.KeyId,
			"alg":       eab.Alg,
			"mac":       eab.Mac,
		},
	}

	_, err := coll.UpdateOne(ctx, bson.D{{Key: "contact", Value: eab.Contact}}, b)
	if err != nil {
		return err
	}
	return nil
}
