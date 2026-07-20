package bgptools

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestQueryRDAPParsesRegistrationAndGeofeed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(`{"handle":"NET-TEST","name":"TEST-NET","country":"US","startAddress":"192.0.2.0","endAddress":"192.0.2.255","cidr0_cidrs":[{"v4prefix":"192.0.2.0","length":24}],"events":[{"eventAction":"registration","eventDate":"2020-01-02T03:04:05Z"}],"links":[{"rel":"geofeed","href":"https://example.test/geofeed.csv"}],"entities":[{"handle":"EXAMPLE","roles":["registrant"]}]}`))
	}))
	defer server.Close()
	record, err := QueryRDAP(context.Background(), "192.0.2.1", server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if record.Handle != "NET-TEST" || record.RegistrationDate == nil || len(record.GeofeedURLs) != 1 || len(record.Entities) != 1 || len(record.Prefixes) != 1 || record.Prefixes[0] != "192.0.2.0/24" {
		t.Fatalf("unexpected record: %+v", record)
	}
}

func TestQueryRDAPRejectsInvalidIP(t *testing.T) {
	if _, err := QueryRDAP(context.Background(), "invalid", nil, ""); err == nil {
		t.Fatal("expected invalid IP error")
	}
}

func TestQueryRDAPCanonicalizesAndFiltersPrefixes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := strings.TrimPrefix(r.URL.Path, "/"); got != "2001:db8::1" {
			t.Errorf("RDAP path IP = %q", got)
		}
		_, _ = w.Write([]byte(`{"port43":"whois.ripe.net","cidr0_cidrs":[{"v6prefix":"2001:db8::99","length":32},{"v6prefix":"2001:db8::"},{"v6prefix":"2001:db9::","length":32},{"v6prefix":"not-an-ip","length":32},{"v6prefix":"2001:db8::","length":129},{"v4prefix":"192.0.2.0","length":24}],"events":[{"eventAction":"registration"}]}`))
	}))
	defer server.Close()

	record, err := QueryRDAP(nil, "2001:db8::1", server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Prefixes) != 1 || record.Prefixes[0] != "2001:db8::/32" {
		t.Fatalf("unexpected filtered prefixes: %+v", record.Prefixes)
	}
}
