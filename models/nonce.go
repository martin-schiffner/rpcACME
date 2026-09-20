package models

import "time"

type Nonce struct {
	Nonce     string    `bson:"nonce" json:"nonce"`
	Realm     string    `bson:"realm" json:"realm"`
	CreatedAt time.Time `bson:"createdAt" json:"createdAt"`
	Reserved  bool      `bson:"reserved" json:"reserved"`
}
