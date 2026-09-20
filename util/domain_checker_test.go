package util

import (
	"testing"
)

func TestIsRegistered(t *testing.T) {
	checker := NewDomainChecker()

	// test if .com domain is registered
	exists, err := checker.IsRegistered("example.com")
	if err != nil {
		t.Error(err)
	}
	if !exists {
		t.Error("domain example.com should be registered")
	}

	// test if .com domain is not registered
	exists, err = checker.IsRegistered("xzszdkanclsno3232cn.com")
	if err != nil {
		t.Error(err)
	}
	if exists {
		t.Error("domain thisdomaindoesnotexists.com should not be registered")
	}
}

func TestIsDeDomainRegistered(t *testing.T) {
	checker := NewDomainChecker()

	// test if .de domain is registered
	exists, err := checker.IsRegistered("denic.de")
	if err != nil {
		t.Error(err)
	}
	if !exists {
		t.Error("domain denic.de should be registered")
	}
}
