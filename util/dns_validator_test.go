package util

import (
	"testing"
)

func TestValidateNoDns(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		wantErr  bool
	}{
		{
			name:     "non-existent host",
			hostname: "this-domain-does-not-exist-12345.com",
			wantErr:  false,
		},
		{
			name:     "existing host",
			hostname: "google.com",
			wantErr:  true,
		},
		{
			name:     "invalid hostname (empty)",
			hostname: "",
			wantErr:  false,
		},
		{
			name:     "invalid hostname",
			hostname: "invalid..hostname",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNoDns(tt.hostname)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateNoDns(%q) error = %v, wantErr %v", tt.hostname, err, tt.wantErr)
			}
		})
	}
}
