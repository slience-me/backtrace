package bgptools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type privacyRoundTripper func(*http.Request) (*http.Response, error)

func (fn privacyRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestStructuredReportErrorsDoNotExposeRemoteURLs(t *testing.T) {
	var rdap *httptest.Server
	rdap = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"handle":"TEST","links":[{"rel":"geofeed","href":"https://private.example/geofeed?token=secret"}]}`)
	}))
	defer rdap.Close()
	failing := &http.Client{Transport: privacyRoundTripper(func(request *http.Request) (*http.Response, error) {
		return nil, errors.New("dial " + request.URL.String())
	})}
	report, err := QueryIPBGPReport(context.Background(), "192.0.2.1", IPBGPReportConfig{
		RDAPClient:    rdap.Client(),
		RDAPBaseURL:   rdap.URL,
		FetchGeofeed:  true,
		GeofeedClient: failing,
		ResolveASN: func(context.Context, string) (string, error) {
			return "", errors.New("resolver https://private.example/asn?key=secret")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range report.Sources {
		for _, field := range []string{source.Source, source.Error} {
			for _, forbidden := range []string{"private.example", "token=", "key=", "secret"} {
				if strings.Contains(field, forbidden) {
					t.Fatalf("structured source leaked %q: %+v", forbidden, source)
				}
			}
		}
	}
	if len(report.Geofeeds) != 1 || report.Geofeeds[0].Error != "request_failed" {
		t.Fatalf("geofeed error was not stabilized: %+v", report.Geofeeds)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"private.example", "token=", "key=", "secret", "userinfo@", `"geofeed_urls"`, `"port43"`, `"server"`, `"url"`} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("structured report leaked %q: %s", forbidden, encoded)
		}
	}
	if report.RDAP == nil || len(report.RDAP.GeofeedURLs) != 1 || report.Geofeeds[0].Status != ReportError {
		t.Fatalf("internal geofeed processing was not preserved: %+v", report)
	}
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

func TestStructuredReportOmitsServiceLocationsButKeepsProbeEvidence(t *testing.T) {
	report := IPBGPReport{
		Status: ReportPartial,
		RDAP: &RDAPRecord{
			Port43:      "whois.private.example:43",
			GeofeedURLs: []string{"https://private.example/rdap-geofeed.csv"},
		},
		WHOIS: &WHOISRecord{
			Server:      "whois.private.example:43",
			Status:      ReportAvailable,
			GeofeedURLs: []string{"https://private.example/whois-geofeed.csv"},
		},
		Geofeeds: []GeofeedResult{{
			URL:        "https://private.example/geofeed.csv",
			Status:     ReportAvailable,
			HTTPStatus: http.StatusOK,
			Bytes:      128,
		}},
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"private.example", "whois.private", `"geofeed_urls"`, `"port43"`, `"server"`, `"url"`} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("structured report leaked %q: %s", forbidden, encoded)
		}
	}
	for _, expected := range []string{`"status":"available"`, `"http_status":200`, `"bytes":128`} {
		if !strings.Contains(string(encoded), expected) {
			t.Fatalf("structured report lost probe evidence %q: %s", expected, encoded)
		}
	}
}
