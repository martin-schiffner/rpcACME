package util

import (
	"errors"
	"net/mail"
	"net/url"
	"time"
)

func IsValidContact(email string) error {
	if email == "" {
		return errors.New("email is empty")
	}

	parsedUrl, err := url.Parse(email)
	if err != nil {
		return err
	}

	if parsedUrl.Scheme != "mailto" {
		return errors.New("contact must start with 'mailto:'")
	}

	_, err = mail.ParseAddress(parsedUrl.Opaque)
	if err != nil {
		return err
	}

	return nil
}

func IsValidEmail(email string) error {
	if email == "" {
		return errors.New("email is empty")
	}

	_, err := mail.ParseAddress(email)
	if err != nil {
		return err
	}
	return nil
}

func IsValid3339Date(dateStr string) error {
	_, err := time.Parse(time.RFC3339, dateStr)
	return err
}
