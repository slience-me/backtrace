package bgptools

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestResolveOriginASNOfflineFixture(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("resource"); got != "192.0.2.1" {
			t.Errorf("resource = %q", got)
		}
		_, _ = w.Write([]byte(`{"status":"ok","data":{"asns":["AS64500",64501],"prefix":"192.0.2.0/24"}}`))
	}))
	defer server.Close()

	asn, err := ResolveOriginASNWithConfig(context.Background(), "192.0.2.1", OriginASNConfig{
		Client: server.Client(), BaseURL: server.URL, Timeout: time.Second,
	})
	if err != nil || asn != "64500" {
		t.Fatalf("ResolveOriginASNWithConfig() = %q, %v", asn, err)
	}
}

func TestResolveOriginASNRejectsMissingAndDriftedData(t *testing.T) {
	for _, payload := range []string{
		`{"status":"ok","data":{"asns":[]}}`,
		`{"status":"ok","data":{"asns":"64500"}}`,
		`{"status":"ok","data":{"asns":["not-an-asn"]}}`,
		`{"status":"error","data":{"asns":[64500]}}`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(payload))
		}))
		_, err := ResolveOriginASNWithConfig(context.Background(), "2001:db8::1", OriginASNConfig{
			Client: server.Client(), BaseURL: server.URL, Timeout: time.Second,
		})
		server.Close()
		if err == nil {
			t.Fatalf("payload %s unexpectedly succeeded", payload)
		}
	}
}

func TestResolveOriginASNReportsRateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	_, err := ResolveOriginASNWithConfig(context.Background(), "192.0.2.1", OriginASNConfig{Client: server.Client(), BaseURL: server.URL})
	if !errors.Is(err, ErrOriginASNRateLimited) {
		t.Fatalf("rate limit error = %v", err)
	}
}
