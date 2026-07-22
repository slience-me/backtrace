package bgptools

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

type privacyRoundTripper func(*http.Request) (*http.Response, error)

func (fn privacyRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestRemoteFetchErrorsDoNotExposeSourceURL(t *testing.T) {
	client := &http.Client{Transport: privacyRoundTripper(func(request *http.Request) (*http.Response, error) {
		return nil, errors.New("dial " + request.URL.String())
	})}
	tests := []struct {
		name string
		run  func() error
	}{
		{name: "ASN metadata", run: func() error {
			_, err := fetchASNMetadata(context.Background(), client, "https://private.example/asn?token=secret")
			return err
		}},
		{name: "RDAP", run: func() error {
			_, err := QueryRDAP(context.Background(), "192.0.2.1", client, "https://private.example/rdap?token=secret")
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.run()
			if err == nil {
				t.Fatal("expected request failure")
			}
			for _, forbidden := range []string{"private.example", "token=", "secret"} {
				if strings.Contains(err.Error(), forbidden) {
					t.Fatalf("error leaked %q: %v", forbidden, err)
				}
			}
		})
	}
}
