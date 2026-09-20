package models

import "time"

type AcmeEAB struct {
	CreatedAt time.Time `json:"createdAt" bson:"createdAt"`
	UpdatedOn time.Time `json:"updatedOn" bson:"updatedOn"`
	KeyId     string    `json:"keyId" bson:"keyId"`
	Mac       string    `json:"mac" bson:"mac"`
	Alg       string    `json:"alg" bson:"alg"`
	Contact   string    `json:"contact" bson:"contact"`
}
