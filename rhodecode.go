package rhodecode

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
)

// Sets the certificate authority to be used in all API requests.
func SetCertAuth(pem []byte) {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	http.DefaultTransport = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: pool,
		},
	}
}

type RhodeCode struct {
	url    string
	apiKey string
}

// Returns a new RhodeCode. 
func New(url, apiKey string) *RhodeCode {
	return &RhodeCode{url, apiKey}
}

func ptrToString(s *string) string {
	if s != nil {
		return *s
	}

	return ""
}

func ptrToInt(v *int) int {
	if v != nil {
		return *v
	}

	return 0
}

func ptrToBool(v *bool) bool {
	if v != nil {
		return *v
	}

	return false
}

func boolToIntString(b bool) string {
	if b {
		return "1"
	}

	return "0"
}

func castError(err interface{}) error {
	str, ok := err.(string)
	if !ok {
		return fmt.Errorf("%+v", err)
	}

	return errors.New(str)
}
