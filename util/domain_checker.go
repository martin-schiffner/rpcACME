package util

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	RdapProxyUrl = "https://rdap.org"
	RdapDenicUrl = "https://rdap.denic.de"
)

type DomainChecker struct {
	client *http.Client
}

func NewDomainChecker() *DomainChecker {
	return &DomainChecker{
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func determineRdapUrl(domain string) string {
	if strings.HasSuffix(strings.ToLower(domain), ".de") {
		return RdapDenicUrl
	}
	return RdapProxyUrl
}

func (c *DomainChecker) IsRegistered(domain string) (bool, error) {
	url := determineRdapUrl(domain) + "/domain/" + domain
	req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("User-Agent", "rpccaCertUI/1.0")
	resp, err := c.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	case http.StatusTooManyRequests:
		return false, fmt.Errorf("rate limit reached")
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
