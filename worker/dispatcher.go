package worker

import (
	"context"
	"fmt"
	"log/slog"
	"rpcca/acme/certservice"
	acmemodel "rpcca/acme/models"
	"time"
)

type Dispatcher struct {
	JobQueue    chan Job
	WorkerPool  chan chan Job
	MaxWorkers  int
	WorkerRepo  WorkerRepository
	CertService certservice.CertService
	Logger      *slog.Logger
}

func NewDispatcher(maxWorkers int, jobQueue chan Job, monogInstance *acmemodel.MongoInstance, cs certservice.CertService, log *slog.Logger) *Dispatcher {
	pool := make(chan chan Job, maxWorkers)
	workerRepo := NewWorkerRepository(monogInstance)
	return &Dispatcher{
		JobQueue:    jobQueue,
		WorkerPool:  pool,
		MaxWorkers:  maxWorkers,
		WorkerRepo:  workerRepo,
		CertService: cs,
		Logger:      log,
	}
}

func (d *Dispatcher) Run() {
	for i := 0; i < d.MaxWorkers; i++ {
		worker := NewWorker(d.WorkerPool, d.WorkerRepo, d.CertService, d.Logger)
		worker.Start()
	}

	go d.dispatch()
}

func (d *Dispatcher) SubmitJob(job Job) (int64, error) {
	if !IsValidJobType(job.JobType) {
		return 0, fmt.Errorf("job type '%s' is not known", job.JobType)
	}

	jobId, err := d.WorkerRepo.GetNewJobId(context.TODO())
	if err != nil {
		return 0, err
	}

	job.JobId = jobId
	job.JobStatus = JOB_STATUS_QUEUED
	job.CreatedAt = time.Now().UTC()

	err = d.WorkerRepo.StoreJob(context.TODO(), job)
	if err != nil {
		return 0, err
	}

	d.JobQueue <- job

	return jobId, nil
}

func (d *Dispatcher) GetJobById(jobId int64) (Job, error) {
	return d.WorkerRepo.GetJobById(context.TODO(), jobId)
}

func (d *Dispatcher) dispatch() {
	for {
		select {
		case job := <-d.JobQueue:
			go func() {
				workerJobQueue := <-d.WorkerPool
				workerJobQueue <- job
			}()
		}
	}
}
