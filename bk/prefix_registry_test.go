package backtrace

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseASNPrefixLinesNormalizesAndDeduplicates(t *testing.T) {
	values, err := parseASNPrefixLines([]byte("2409:8000\n2409:8000\n2401:db8::/32\n"))
	if err != nil || len(values) != 2 || values[0] != "2401:db8::/32" {
		t.Fatalf("unexpected prefixes: %#v, %v", values, err)
	}
}

func TestLoadASNPrefixRegistryUsesRawAfterCDNFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		path := strings.TrimPrefix(request.URL.Path, "/")
		parts := strings.Split(path, "/")
		if len(parts) != 2 {
			http.NotFound(writer, request)
			return
		}
		base, file := parts[0], parts[1]
		snapshot := []byte("2409:8000\n")
		if base == "bad" && file == "as23764.txt.manifest.json" {
			_, _ = writer.Write([]byte(`{}`))
			return
		}
		if strings.HasSuffix(file, ".manifest.json") {
			hash := sha256.Sum256(snapshot)
			manifest, _ := json.Marshal(prefixManifest{Schema: ASNPrefixRegistrySchema, File: strings.TrimSuffix(file, ".manifest.json"), Count: 1, SHA256: hex.EncodeToString(hash[:]), GeneratedAt: "2026-01-01T00:00:00Z"})
			_, _ = writer.Write(manifest)
			return
		}
		_, _ = writer.Write(snapshot)
	}))
	defer server.Close()
	sources := []ASNPrefixRegistrySource{{Name: "cdn", Base: server.URL + "/bad", ValidateManifest: true}, {Name: "raw", Base: server.URL + "/good", ValidateManifest: true}}
	loaded, err := LoadASNPrefixRegistry(context.Background(), server.Client(), sources)
	if err != nil || loaded.Source != "raw" || !loaded.Fallback || len(loaded.Prefixes) != len(knownPrefixASNs) {
		t.Fatalf("unexpected load: %+v, %v", loaded, err)
	}
}

func TestValidatePrefixManifestRejectsHashAndCountMismatch(t *testing.T) {
	snapshot := []byte("2409:8000\n")
	manifest := prefixManifest{Schema: ASNPrefixRegistrySchema, File: "as23764.txt", Count: 2, SHA256: strings.Repeat("0", 64), GeneratedAt: "2026-01-01T00:00:00Z"}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePrefixManifest(data, snapshot, "as23764.txt"); err == nil {
		t.Fatal("invalid manifest unexpectedly accepted")
	}
}

func TestValidateEmbeddedPrefixManifests(t *testing.T) {
	if err := validateEmbeddedPrefixManifests(); err != nil {
		t.Fatal(err)
	}
}

func TestEmbeddedManifestFilesArePresent(t *testing.T) {
	for _, asn := range knownPrefixASNs {
		name := strings.ToLower(asn) + ".txt.manifest.json"
		if _, err := embeddedPrefixManifestFS.ReadFile(filepath.Join("prefix", name)); err != nil {
			t.Fatalf("missing embedded manifest %s: %v", name, err)
		}
	}
}

func TestLoadASNPrefixRegistryEmbeddedFallback(t *testing.T) {
	loaded, err := LoadASNPrefixRegistry(context.Background(), nil, nil)
	if err != nil || loaded.Source != "embedded" || !loaded.Fallback || len(loaded.Prefixes) == 0 {
		t.Fatalf("unexpected embedded load: %+v, %v", loaded, err)
	}
}
