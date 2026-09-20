package models

import (
	"context"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type MongoInstance struct {
	Client *mongo.Client
	Db     *mongo.Database
}

func Connect(mongoUri string, dbName string) (MongoInstance, error) {
	client, err := mongo.Connect(options.Client().ApplyURI(mongoUri))

	if err != nil {
		return MongoInstance{}, err
	}

	db := client.Database(dbName)

	mi := MongoInstance{
		Client: client,
		Db:     db,
	}

	return mi, nil
}

func Disconnect(mi MongoInstance) error {
	if mi.Client == nil {
		return nil
	}

	err := mi.Client.Disconnect(context.TODO())

	return err
}
