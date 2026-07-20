package backtrace

import (
	"context"
	"net/http"
	"net/http/httptest"
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
		if request.URL.Path == "/bad/as23764.txt" {
			http.Error(writer, "bad", http.StatusBadGateway)
			return
		}
		_, _ = writer.Write([]byte("2409:8000\n"))
	}))
	defer server.Close()
	sources := []ASNPrefixRegistrySource{{Name: "cdn", Base: server.URL + "/bad"}, {Name: "raw", Base: server.URL + "/good"}}
	loaded, err := LoadASNPrefixRegistry(context.Background(), server.Client(), sources)
	if err != nil || loaded.Source != "raw" || !loaded.Fallback || len(loaded.Prefixes) != len(knownPrefixASNs) {
		t.Fatalf("unexpected load: %+v, %v", loaded, err)
	}
}

func TestLoadASNPrefixRegistryEmbeddedFallback(t *testing.T) {
	loaded, err := LoadASNPrefixRegistry(context.Background(), nil, nil)
	if err != nil || loaded.Source != "embedded" || !loaded.Fallback || len(loaded.Prefixes) == 0 {
		t.Fatalf("unexpected embedded load: %+v, %v", loaded, err)
	}
}
