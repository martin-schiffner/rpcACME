package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"rpcca/acme/certservice"
	"rpcca/acme/util"
	"time"

	"github.com/go-playground/validator/v10"
)

const (
	MaxHttp01ResponseLength = 8 * 1024
)

type JobValidateHttp01Input struct {
	Server string `json:"server"`
	Token  string `json:"token"`
}

type JobValidateDns01Input struct {
	DomainName    string `json:"domain_name"`
	Token         string `json:"token"`
	KeyThumbprint string `json:"key_thumbprint"`
}

type JobValidateDns01Output struct {
	TxtRecords []string `json:"txt_records"`
}

type JobIssueCertificateInput struct {
	CertificateRequest certservice.CertificateRequest
}

type JobRevokeCertificateInput struct {
	CaName      string
	Fingerprint string
	Reason      string
	Filter      map[string]string
	OrFilter    map[string][]string
}

type JobIssueCertificateOutput struct {
	Status                 string `json:"status"`
	Detail                 string `json:"detail"`
	CertificatePem         string `json:"certPem"`
	CertificateChain       string `json:"certChain"`
	CertificateFingerprint string `json:"certFingerprint"`
}

func validateHttp01Vars(hostname string, token string) error {
	validate := validator.New()
	// validate server name
	err := validate.Var(hostname, "required,hostname,max=2048")
	if err != nil {
		return err
	}

	err = validate.Var(token, "required,alphanum,max=2048")
	if err != nil {
		return err
	}
	return nil
}

// ValidateHttp01 implements the steps for performing the ACME http-01 validation
func ValidateHttp01(w *Worker, jobId int64, input string) error {
	var jobInput JobValidateHttp01Input
	err := json.Unmarshal([]byte(input), &jobInput)
	if err != nil {
		e := w.WorkerRepo.UpdateJobStatus(context.TODO(), jobId, JOB_STATUS_FAILED, err.Error())
		return errors.Join(err, e)
	}

	// validate server and token
	err = validateHttp01Vars(jobInput.Server, jobInput.Token)
	if err != nil {
		return w.WorkerRepo.UpdateJobStatus(context.TODO(), jobId, JOB_STATUS_FAILED, err.Error())
	}

	u := &url.URL{
		Scheme: "http",
		Host:   jobInput.Server + ":80",
		Path:   "/.well-known/acme-challenge/" + jobInput.Token,
	}

	w.Logger.Debug("client's validation url", slog.String("url", u.String()))

	headers := map[string][]string{
		"User-Agent": {HTTP01_USER_AGENT},
		"Accept":     {"application/octet-stream"},
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DisableCompression: true,
			Proxy:              nil,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// there are no redirects allowed
			return http.ErrUseLastResponse
		},
	}
	request := &http.Request{
		Method: "GET",
		URL:    u,
		Header: headers,
	}
	resp, err := client.Do(request)
	if err != nil {
		e := w.WorkerRepo.UpdateJobStatus(context.TODO(), jobId, JOB_STATUS_FAILED, err.Error())
		return errors.Join(err, e)
	}

	//body, err := io.ReadAll(resp.Body)
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxHttp01ResponseLength))
	if err != nil { // handle errors during read response
		err = resp.Body.Close()
		return err
	}
	err = resp.Body.Close()
	if err != nil { // handle response body close issues
		return err
	}

	if resp.StatusCode != http.StatusOK {
		e := w.WorkerRepo.UpdateJobStatus(context.TODO(), jobId, JOB_STATUS_FAILED, "expected status code 200, got: "+resp.Status)
		return errors.Join(err, e)
	}

	body = bytes.TrimSpace(body)
	err = w.WorkerRepo.UpdateJobStatus(context.TODO(), jobId, JOB_STATUS_FINISHED, string(body))
	if err != nil {
		return err
	}
	return nil
}

// ValidateDns01 implements the steps for performing the ACME dns-01 validation
func ValidateDns01(w Worker, jobId int64, input string) error {
	var jobInput JobValidateDns01Input
	err := json.Unmarshal([]byte(input), &jobInput)
	if err != nil {
		e := w.WorkerRepo.UpdateJobStatus(context.TODO(), jobId, JOB_STATUS_FAILED, err.Error())
		return errors.Join(err, e)
	}

	acmeTxtRecord := "_acme-challenge." + jobInput.DomainName
	res, err := net.LookupTXT(acmeTxtRecord)
	if err != nil {
		e := w.WorkerRepo.UpdateJobStatus(context.TODO(), jobId, JOB_STATUS_FAILED, err.Error())
		return errors.Join(err, e)
	}

	if len(res) == 0 {
		e := fmt.Errorf("no TXT record found for %s", acmeTxtRecord)
		e2 := w.WorkerRepo.UpdateJobStatus(context.TODO(), jobId, JOB_STATUS_FAILED, e.Error())
		return errors.Join(e, e2)
	}

	jobOut := JobValidateDns01Output{
		TxtRecords: res,
	}

	o, err := json.Marshal(jobOut)
	if err != nil {
		e := w.WorkerRepo.UpdateJobStatus(context.TODO(), jobId, JOB_STATUS_FAILED, err.Error())
		return errors.Join(err, e)
	}
	return w.WorkerRepo.UpdateJobStatus(context.TODO(), jobId, JOB_STATUS_FINISHED, string(o))
}

func ValidNoDns01(w Worker, jobId int64, input string) error {
	var jobInput JobValidateDns01Input
	err := json.Unmarshal([]byte(input), &jobInput)
	if err != nil {
		e := w.WorkerRepo.UpdateJobStatus(context.TODO(), jobId, JOB_STATUS_FAILED, err.Error())
		if e != nil {
			return errors.Join(err, e)
		}
		return err
	}

	err = util.ValidateNoDns(jobInput.DomainName)
	if err != nil {
		return w.WorkerRepo.UpdateJobStatus(context.TODO(), jobId, JOB_STATUS_FAILED, err.Error())
	}

	statusOk := "{\"status\": \"ok\"}"
	return w.WorkerRepo.UpdateJobStatus(context.TODO(), jobId, JOB_STATUS_FINISHED, statusOk)
}

func constructJobOutputJson(status string, detail string, cert string, chain string, fp string) (string, error) {
	output := JobIssueCertificateOutput{
		Status:                 status,
		Detail:                 detail,
		CertificatePem:         cert,
		CertificateChain:       chain,
		CertificateFingerprint: fp,
	}

	outputBytes, err := json.Marshal(output)
	if err != nil {
		return "", err
	}
	return string(outputBytes), nil
}

// IssueCertificate implements the steps for sending a certificate request to the CA and retrieve the certificate
func IssueCertificate(w Worker, jobId int64, input string) error {
	var jobInput JobIssueCertificateInput

	err := json.Unmarshal([]byte(input), &jobInput)
	if err != nil {
		e := w.WorkerRepo.UpdateJobStatus(context.TODO(), jobId, JOB_STATUS_FAILED, err.Error())
		return errors.Join(err, e)
	}

	// submit request to CA
	resp, err := w.CertService.RequestCertificate(context.TODO(), jobInput.CertificateRequest)
	if err != nil {
		e := fmt.Errorf("unable to get certificate from ca: %w", err)
		out, ce := constructJobOutputJson(JOB_STATUS_FAILED, e.Error(), "", "", "")
		if ce != nil {
			e = errors.Join(ce, e)
		}
		uE := w.WorkerRepo.UpdateJobStatus(context.TODO(), jobId, JOB_STATUS_FAILED, out)
		return errors.Join(e, uE)
	}

	// convert pem to der
	block, _ := pem.Decode([]byte(resp.Certificate))
	if block == nil {
		out, ce := constructJobOutputJson(JOB_STATUS_FAILED, "failed to parse certificate PEM", "", "", "")
		if ce != nil {
			return w.WorkerRepo.UpdateJobStatus(context.TODO(), jobId, JOB_STATUS_FAILED, ce.Error())
		}
		return w.WorkerRepo.UpdateJobStatus(context.TODO(), jobId, JOB_STATUS_FAILED, out)
	}

	// calculate fingerprint of the der
	fp := util.CalculateCertFingerprint(block)

	// get chain for this certificate
	chain, err := w.CertService.GetCertCaChain(context.TODO(), fp)
	if err != nil {
		out, ce := constructJobOutputJson(JOB_STATUS_FAILED, err.Error(), "", "", "")
		if ce != nil {
			err = errors.Join(ce, err)
		}
		e := w.WorkerRepo.UpdateJobStatus(context.TODO(), jobId, JOB_STATUS_FAILED, out)
		return errors.Join(err, e)
	}

	var certChain string

	for _, cert := range chain {
		if len(certChain) == 0 {
			certChain = cert.CertPem
		} else {
			certChain += "\n" + cert.CertPem
		}
	}

	out, ce := constructJobOutputJson(JOB_STATUS_FINISHED, "", resp.Certificate, certChain, fp)
	if ce != nil {
		return w.WorkerRepo.UpdateJobStatus(context.TODO(), jobId, JOB_STATUS_FAILED, ce.Error())
	}
	return w.WorkerRepo.UpdateJobStatus(context.TODO(), jobId, JOB_STATUS_FINISHED, out)
}

func RevokeCertificate(w Worker, jobId int64, input string) error {
	var jobInput JobRevokeCertificateInput

	err := json.Unmarshal([]byte(input), &jobInput)
	if err != nil {
		e := w.WorkerRepo.UpdateJobStatus(context.TODO(), jobId, JOB_STATUS_FAILED, err.Error())
		return errors.Join(err, e)
	}

	err = w.CertService.RevokeCertificate(context.TODO(), jobInput.CaName, jobInput.Fingerprint, jobInput.Reason, jobInput.Filter, jobInput.OrFilter)
	if err != nil {
		e := fmt.Errorf("unable to revoke certificate: %w", err)
		out, ce := constructJobOutputJson(JOB_STATUS_FAILED, e.Error(), "", "", "")
		if ce != nil {
			err = errors.Join(ce, e)
		}
		ue := w.WorkerRepo.UpdateJobStatus(context.TODO(), jobId, JOB_STATUS_FAILED, out)
		return errors.Join(e, ue)
	}

	statusOk := "{\"status\": \"ok\"}"
	return w.WorkerRepo.UpdateJobStatus(context.TODO(), jobId, JOB_STATUS_FINISHED, statusOk)
}

// TODO: add jobs for:
// - cleaning up expired orders, authorizations, challengdes, nonces
