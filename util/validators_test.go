package util

import (
	"testing"
)

func TestIsValidContact(t *testing.T) {
	// negative test cases
	tests := []struct {
		name  string
		email string
	}{
		{
			name:  "Invalid email without mailto",
			email: "example@example.com",
		},
		{
			name:  "Empty email",
			email: "",
		},
		{
			name:  "Invalid email format",
			email: "mailto:invalid-email",
		},
		{
			name:  "Missing email after mailto",
			email: "mailto:",
		},
		{
			name:  "Invalid scheme",
			email: "http://example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := IsValidContact(tt.email)
			if err == nil {
				t.Errorf("IsValidContact() error = %v", err)
			}
		})
	}

	// positive test cases
	testsPos := []struct {
		name  string
		email string
	}{
		{
			name:  "Valid 1",
			email: "mailto: example@example.com",
		},
		{
			name:  "Valid 2",
			email: "mailto:max.muster@example.com",
		},
		{
			name:  "Valid 3",
			email: "mailto:max-muster@example.com",
		},
	}

	for _, tt := range testsPos {
		t.Run(tt.name, func(t *testing.T) {
			err := IsValidContact(tt.email)
			if err != nil {
				t.Errorf("IsValidContact() error = %v", err)
			}
		})
	}
}
