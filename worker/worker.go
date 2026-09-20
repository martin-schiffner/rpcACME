package worker

import (
	"log/slog"
	"rpcca/acme/certservice"
	"time"
)

const (
	MAX_WORKER = 4
	MAX_QUEUE  = 40

	JOB_STATUS_QUEUED   = "queued"
	JOB_STATUS_FINISHED = "finished"
	JOB_STATUS_FAILED   = "failed"

	HTTP01_USER_AGENT = "rpcCAcme-Server"
)

type Job struct {
	JobType    JobType       `bson:"jobType"`
	JobId      int64         `bson:"jobId"`
	JobInput   string        `bson:"jobInput"`
	JobOutput  string        `bson:"jobOutput"`
	JobStatus  string        `bson:"jobStatus"`
	ExternalId string        `bson:"externalId"`
	CreatedAt  time.Time     `bson:"createdAt"`
	UpdatedOn  time.Time     `bson:"updatedOn"`
	Done       chan struct{} `bson:"-" json:"-"` // Optional: closed when job is finished
}

type Worker struct {
	WorkerPool  chan chan Job
	JobChannel  chan Job
	WorkerRepo  WorkerRepository
	CertService certservice.CertService
	Logger      *slog.Logger
	quit        chan bool
}

func NewWorker(workerPool chan chan Job, workerRepo WorkerRepository, cs certservice.CertService, log *slog.Logger) Worker {
	return Worker{
		WorkerPool:  workerPool,
		JobChannel:  make(chan Job),
		WorkerRepo:  workerRepo,
		CertService: cs,
		Logger:      log,
		quit:        make(chan bool),
	}
}

func (w Worker) Start() {
	go func() {
		for {
			w.WorkerPool <- w.JobChannel
			select {
			case job := <-w.JobChannel:
				switch job.JobType {
				case JOB_TYPE_ACME_HTTP01VALIDATION:
					err := ValidateHttp01(&w, job.JobId, job.JobInput)
					if err != nil {
						w.Logger.Error("error running job:", slog.Any("err", err))
					}
				case JOB_TYPE_ACME_DNS01VALIDATION:
					err := ValidateDns01(w, job.JobId, job.JobInput)
					if err != nil {
						w.Logger.Error("error running job:", slog.Any("err", err))
					}
				case JOB_TYPE_ACME_NODNS01VALIDATION:
					err := ValidNoDns01(w, job.JobId, job.JobInput)
					if err != nil {
						w.Logger.Error("error running job:", slog.Any("err", err))
					}
				case JOB_TYPE_CERT_REQUEST:
					err := IssueCertificate(w, job.JobId, job.JobInput)
					if err != nil {
						w.Logger.Error("error running issue_certificate job:", slog.Any("err", err))
					}
				case JOB_TYPE_CERT_REVOKE:
					err := RevokeCertificate(w, job.JobId, job.JobInput)
					if err != nil {
						w.Logger.Error("error executing cert_revoke job:", slog.Any("err", err))
					}
				case JOBY_TYPE_DUMMY:
					w.Logger.Info("dummy job executed", slog.Int64("jobId", job.JobId))
				default:
					w.Logger.Error("job type unknown")
				}
				// Notify if Done channel is set
				if job.Done != nil {
					close(job.Done)
				}
			case <-w.quit:
				return
			}
		}
	}()
}
