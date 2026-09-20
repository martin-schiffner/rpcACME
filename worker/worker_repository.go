package worker

import (
	"context"
	"errors"
	certuimodel "rpcca/acme/models"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

const (
	CollectionIds  = "auto_incr_ids"
	CollectionJobs = "jobs"
)

type JobId struct {
	Id int64 `bson:"jobId"`
}

type mongoRepository struct {
	mongoInstance *certuimodel.MongoInstance
}

type WorkerRepository interface {
	GetNewJobId(ctx context.Context) (int64, error)

	GetJobById(ctx context.Context, jobId int64) (Job, error)
	GetJobByExternalId(ctx context.Context, externalId string) (Job, error)
	StoreJob(ctx context.Context, job Job) error
	UpdateJobStatus(ctx context.Context, jobId int64, jobStatus string, jobOutput string) error
}

func NewWorkerRepository(mongoInstance *certuimodel.MongoInstance) WorkerRepository {
	return &mongoRepository{
		mongoInstance: mongoInstance,
	}
}

func (m *mongoRepository) GetNewJobId(ctx context.Context) (int64, error) {
	coll := m.mongoInstance.Db.Collection(CollectionIds)

	var jobId JobId
	err := coll.FindOneAndUpdate(ctx, bson.D{{}}, bson.M{"$inc": bson.D{{Key: "jobId", Value: 1}}}).Decode(&jobId)
	if err != nil {
		return 0, err
	}

	return jobId.Id, nil
}

func (m *mongoRepository) GetJobById(ctx context.Context, jobId int64) (Job, error) {
	coll := m.mongoInstance.Db.Collection(CollectionJobs)

	var job Job
	err := coll.FindOne(ctx, bson.D{{Key: "jobId", Value: jobId}}).Decode(&job)
	if err != nil {
		return Job{}, err
	}
	return job, nil
}

func (m *mongoRepository) GetJobByExternalId(ctx context.Context, externalId string) (Job, error) {
	coll := m.mongoInstance.Db.Collection(CollectionJobs)

	var job Job
	err := coll.FindOne(ctx, bson.D{{Key: "externalId", Value: externalId}}).Decode(&job)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return job, nil
		}
		return job, err
	}
	return job, nil
}

func (m *mongoRepository) StoreJob(ctx context.Context, job Job) error {
	coll := m.mongoInstance.Db.Collection(CollectionJobs)

	_, err := coll.InsertOne(ctx, job)
	if err != nil {
		return err
	}

	return nil
}

func (m *mongoRepository) UpdateJobStatus(ctx context.Context, jobId int64, jobStatus string, jobOutput string) error {
	coll := m.mongoInstance.Db.Collection(CollectionJobs)

	updates := bson.D{
		{Key: "jobStatus", Value: jobStatus},
		{Key: "jobOutput", Value: jobOutput},
		{Key: "updatedOn", Value: time.Now().UTC()},
	}

	_, err := coll.UpdateOne(ctx, bson.D{{Key: "jobId", Value: jobId}}, bson.M{"$set": updates})
	if err != nil {
		return err
	}

	return nil
}
