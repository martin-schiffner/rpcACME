package models

type ClientRequest struct {
	Protected string `json:"protected"`
	Signature string `json:"signature"`
	Payload   string `json:"payload"`
}
