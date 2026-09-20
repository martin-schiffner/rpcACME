package worker

import "slices"

type JobType string

const (
	JOBY_TYPE_DUMMY                 JobType = "dummy"
	JOB_TYPE_ACME_HTTP01VALIDATION  JobType = "acme_http01_validation"
	JOB_TYPE_ACME_DNS01VALIDATION   JobType = "acme_dns01_validation"
	JOB_TYPE_ACME_NODNS01VALIDATION JobType = "acme_nodns01_validation"
	JOB_TYPE_CERT_REQUEST           JobType = "cert_issuance"
	JOB_TYPE_CERT_REVOKE            JobType = "cert_revocation"
)

var jobTypes = []JobType{
	JOBY_TYPE_DUMMY,
	JOB_TYPE_ACME_HTTP01VALIDATION,
	JOB_TYPE_ACME_DNS01VALIDATION,
	JOB_TYPE_ACME_NODNS01VALIDATION,
	JOB_TYPE_CERT_REQUEST,
	JOB_TYPE_CERT_REVOKE,
}

func IsValidJobType(jt JobType) bool {
	return slices.Contains(jobTypes, jt)
}
