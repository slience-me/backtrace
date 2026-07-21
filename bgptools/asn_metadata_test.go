package bgptools

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoadASNMetadataPrefersValidatedRemote(t *testing.T) {
	payload := `{"schema":"backtrace.asn-metadata/v1","generated_at":"2026-07-20T00:00:00Z","entries":[{"asn":2,"name":"Two"},{"asn":1,"name":"One"}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(payload)) }))
	defer server.Close()
	entries, source, err := loadASNMetadata(context.Background(), server.Client(), []string{server.URL}, []byte(payload), 1)
	if err != nil {
		t.Fatal(err)
	}
	if source.Source != "remote" || source.Fallback || source.Count != 2 || entries[0].ASN != 1 {
		t.Fatalf("unexpected result: %#v %#v", entries, source)
	}
}

func TestLoadASNMetadataFallsBackOnSchemaFailure(t *testing.T) {
	embedded := `{"schema":"backtrace.asn-metadata/v1","generated_at":"2026-07-20T00:00:00Z","entries":[{"asn":1,"name":"One"}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"schema":"wrong"}`)) }))
	defer server.Close()
	entries, source, err := loadASNMetadata(context.Background(), server.Client(), []string{server.URL}, []byte(embedded), 1)
	if err != nil {
		t.Fatal(err)
	}
	if source.Source != "embedded" || !source.Fallback || len(entries) != 1 {
		t.Fatalf("unexpected fallback: %#v %#v", entries, source)
	}
}

func TestParseASNMetadataRejectsDuplicateAndDrop(t *testing.T) {
	payload := []byte(`{"schema":"backtrace.asn-metadata/v1","generated_at":"2026-07-20T00:00:00Z","entries":[{"asn":1,"name":"One"},{"asn":1,"name":"Again"}]}`)
	if _, _, err := parseASNMetadataDocument(payload, 1); err == nil {
		t.Fatal("duplicate ASN unexpectedly accepted")
	}
}
