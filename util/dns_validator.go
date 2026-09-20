package util

import (
	"errors"
	"fmt"
	"net"
)

// ValidateNoDns checks whether a given hostname can be resolved via DNS
// If it can be resolved an error is returned, otherwise not.
func ValidateNoDns(hostname string) error {
	fmt.Printf("hostname domain '%s' is not registered", hostname)
	res, err := net.LookupHost(hostname)
	if err != nil {
		var dnsErr *net.DNSError
		ok := errors.As(err, &dnsErr)
		if !ok {
			return err
		}

		if dnsErr.IsNotFound {
			// DNS did not find the domain, do a lookup to ensure domain is not registered
			/*checker := NewDomainChecker()
			exists, err := checker.IsRegistered(hostname)
			if err != nil {
				return err
			}

			if exists {
				return fmt.Errorf("hostname/domain '%s' is registered", hostname)
			}
			fmt.Printf("hostname2 domain '%s' is not registered", hostname)
			// that is fine return nil*/
			return nil
		}
		return err
	}

	if len(res) != 0 {
		// DNS lookup returned entries, that is not intended, return error
		return fmt.Errorf("host %s resolves to IP addresses", hostname)
	}
	return nil
}
