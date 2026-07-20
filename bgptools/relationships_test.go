package bgptools

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestQueryASNRelationshipsFixture(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/ripe":
			if got := r.URL.Query().Get("resource"); got != "64500" {
				t.Errorf("resource query = %q", got)
			}
			_, _ = w.Write([]byte(`{"data":{"neighbours":[{"asn":64501,"name":"Transit Example","relationship":"upstream","power":12.5},{"asn":"64502","name":"Peer Example","type":"peer","power":3.25},{"asn":64500,"name":"target"}]}}`))
		case "/peering":
			if got := r.URL.Query().Get("asn"); got != "64500" {
				t.Errorf("asn query = %q", got)
			}
			_, _ = w.Write([]byte(`{"data":[{"id":101,"ix_id":7,"name":"Example IX"},{"ixlan":{"id":202,"name":"Nested IX"}}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	report, err := QueryASNRelationships(context.Background(), "AS64500", RelationshipConfig{
		Client:       server.Client(),
		RIPEstatURL:  server.URL + "/ripe",
		PeeringDBURL: server.URL + "/peering",
		Timeout:      time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.TargetASN != "64500" || report.Status != RelationshipAvailable {
		t.Fatalf("unexpected report status: %+v", report)
	}
	if len(report.Upstreams) != 1 || report.Upstreams[0].ASN != "64501" || report.Upstreams[0].Source != "ripestat" {
		t.Fatalf("unexpected upstreams: %+v", report.Upstreams)
	}
	if len(report.Peers) != 1 || report.Peers[0].ASN != "64502" {
		t.Fatalf("unexpected peers: %+v", report.Peers)
	}
	if len(report.IXPs) != 2 || report.IXPs[0].Kind != RelationshipIXP {
		t.Fatalf("unexpected IXPs: %+v", report.IXPs)
	}
	for _, source := range report.SourceStatuses {
		if source.Status != RelationshipAvailable || source.RateLimited || source.Timeout {
			t.Fatalf("unexpected source status: %+v", source)
		}
	}
}

func TestQueryASNRelationshipsRateLimitAndTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/limited":
			w.WriteHeader(http.StatusTooManyRequests)
		case "/slow":
			<-r.Context().Done()
		default:
			_, _ = w.Write([]byte(`{"data":[]}`))
		}
	}))
	defer server.Close()

	limited, err := QueryASNRelationships(context.Background(), "64500", RelationshipConfig{
		Client:       server.Client(),
		RIPEstatURL:  server.URL + "/limited",
		PeeringDBURL: server.URL + "/peering",
		Timeout:      time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if limited.Status != RelationshipPartial || !limited.RateLimited {
		t.Fatalf("expected partial rate-limited report: %+v", limited)
	}
	if status := sourceStatusByName(limited, "ripestat"); status.Status != RelationshipRateLimited || !status.RateLimited || status.Timeout {
		t.Fatalf("unexpected rate-limit source: %+v", status)
	}

	timed, err := QueryASNRelationships(context.Background(), "64500", RelationshipConfig{
		Client:       server.Client(),
		RIPEstatURL:  server.URL + "/slow",
		PeeringDBURL: server.URL + "/slow",
		Timeout:      20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if timed.Status != RelationshipTimeout || !timed.Timeout {
		t.Fatalf("expected timeout report: %+v", timed)
	}
	for _, source := range timed.SourceStatuses {
		if source.Status != RelationshipTimeout || !source.Timeout || source.RateLimited {
			t.Fatalf("unexpected timeout source: %+v", source)
		}
	}
}

func TestQueryASNRelationshipsFieldDrift(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/ripe" {
			_, _ = w.Write([]byte(`{"data":{"neighbors":[]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"results":[]}`))
	}))
	defer server.Close()

	report, err := QueryASNRelationships(context.Background(), "64500", RelationshipConfig{
		Client:       server.Client(),
		RIPEstatURL:  server.URL + "/ripe",
		PeeringDBURL: server.URL + "/peering",
		Timeout:      time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != RelationshipMissingFields {
		t.Fatalf("expected missing_fields report: %+v", report)
	}
	for _, source := range report.SourceStatuses {
		if source.Status != RelationshipMissingFields {
			t.Fatalf("expected missing_fields source, got %+v", source)
		}
	}
}

func TestQueryASNRelationshipsContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	_, err := QueryASNRelationships(ctx, "64500", RelationshipConfig{
		Client:       server.Client(),
		RIPEstatURL:  server.URL,
		PeeringDBURL: server.URL,
		Timeout:      time.Second,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if time.Since(started) > 200*time.Millisecond {
		t.Fatalf("cancellation was not immediate: %v", time.Since(started))
	}
}

func TestNormalizeASN(t *testing.T) {
	for _, input := range []string{"AS64500", " as64500 ", "64500"} {
		if got, err := normalizeASN(input); err != nil || got != "64500" {
			t.Fatalf("normalizeASN(%q) = %q, %v", input, got, err)
		}
	}
	for _, input := range []string{"", "AS0", "AS4294967296", "AS-not-an-asn"} {
		if _, err := normalizeASN(input); err == nil {
			t.Fatalf("normalizeASN(%q) unexpectedly succeeded", input)
		}
	}
}

func sourceStatusByName(report *ASNRelationshipReport, name string) RelationshipSourceStatus {
	for _, source := range report.SourceStatuses {
		if strings.EqualFold(source.Source, name) {
			return source
		}
	}
	return RelationshipSourceStatus{Source: name, Status: RelationshipError}
}
