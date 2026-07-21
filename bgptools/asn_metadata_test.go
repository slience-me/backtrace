package bgptools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLoadASNMetadataPrefersValidatedRemote(t *testing.T) {
	payload := `{"schema":"backtrace.asn-metadata/v1","generated_at":"2026-07-20T00:00:00Z","entries":[{"asn":2,"name":"Two"},{"asn":1,"name":"One"}]}`
	manifest := manifestFor([]byte(payload), "bgp-asn-map.json", 2)
	if err := validateASNMetadataManifest(manifest, []byte(payload), 2, time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, ".manifest.json") {
			_, _ = w.Write(manifest)
			return
		}
		_, _ = w.Write([]byte(payload))
	}))
	defer server.Close()
	entries, source, err := loadASNMetadata(context.Background(), server.Client(), []string{server.URL + "/bgp-asn-map.json"}, []byte(payload), manifest, 1)
	if err != nil {
		t.Fatal(err)
	}
	if source.Source != "cdn" || source.Fallback || source.Count != 2 || entries[0].ASN != 1 {
		t.Fatalf("unexpected result: %#v %#v", entries, source)
	}
}

func TestLoadASNMetadataFallsBackOnSchemaFailure(t *testing.T) {
	embedded := `{"schema":"backtrace.asn-metadata/v1","generated_at":"2026-07-20T00:00:00Z","entries":[{"asn":1,"name":"One"}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"schema":"wrong"}`)) }))
	defer server.Close()
	manifest := manifestFor([]byte(embedded), "bgp-asn-map.json", 1)
	entries, source, err := loadASNMetadata(context.Background(), server.Client(), []string{server.URL + "/bgp-asn-map.json"}, []byte(embedded), manifest, 1)
	if err != nil {
		t.Fatal(err)
	}
	if source.Source != "embedded" || !source.Fallback || len(entries) != 1 {
		t.Fatalf("unexpected fallback: %#v %#v", entries, source)
	}
}

func TestLoadASNMetadataFallsBackFromCDNToRaw(t *testing.T) {
	payload := []byte(`{"schema":"backtrace.asn-metadata/v1","generated_at":"2026-07-20T00:00:00Z","entries":[{"asn":1,"name":"One"}]}`)
	validManifest := manifestFor(payload, "bgp-asn-map.json", 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/cdn/bgp-asn-map.manifest.json" {
			_, _ = writer.Write([]byte(`{"schema":"backtrace.asn-metadata-manifest/v1","file":"bgp-asn-map.json","count":1,"sha256":"bad","generated_at":"2026-07-20T00:00:00Z"}`))
			return
		}
		if request.URL.Path == "/raw/bgp-asn-map.manifest.json" {
			_, _ = writer.Write(validManifest)
			return
		}
		_, _ = writer.Write(payload)
	}))
	defer server.Close()
	entries, source, err := loadASNMetadata(context.Background(), server.Client(), []string{server.URL + "/cdn/bgp-asn-map.json", server.URL + "/raw/bgp-asn-map.json"}, payload, validManifest, 1)
	if err != nil || len(entries) != 1 || source.Source != "raw" || !source.Fallback {
		t.Fatalf("unexpected raw fallback: entries=%#v source=%#v err=%v", entries, source, err)
	}
}

func manifestFor(snapshot []byte, file string, count int) []byte {
	hash := sha256.Sum256(snapshot)
	return []byte(fmt.Sprintf(`{"schema":"backtrace.asn-metadata-manifest/v1","file":"%s","count":%d,"sha256":"%s","generated_at":"2026-07-20T00:00:00Z"}`, file, count, hex.EncodeToString(hash[:])))
}

func TestParseASNMetadataRejectsDuplicateAndDrop(t *testing.T) {
	payload := []byte(`{"schema":"backtrace.asn-metadata/v1","generated_at":"2026-07-20T00:00:00Z","entries":[{"asn":1,"name":"One"},{"asn":1,"name":"Again"}]}`)
	if _, _, err := parseASNMetadataDocument(payload, 1); err == nil {
		t.Fatal("duplicate ASN unexpectedly accepted")
	}
}
