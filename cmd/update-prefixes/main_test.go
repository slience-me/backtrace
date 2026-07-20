package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractIPv6Prefixes(t *testing.T) {
	values, err := extractIPv6Prefixes([]byte(`{"status":"ok","data":{"resource":"64500","prefixes":[{"prefix":"2409:8000::/32"},{"prefix":"2409:8000::/32"},{"prefix":"192.0.2.0/24"}]}}`))
	if err != nil || len(values) != 1 || values[0] != "2409:8000::/32" {
		t.Fatalf("unexpected prefixes: %#v, %v", values, err)
	}
}

func TestExtractIPv6PrefixesRejectsSchemaDrift(t *testing.T) {
	if _, err := extractIPv6Prefixes([]byte(`{"status":"ok","data":{"resource":"64500"}}`)); err == nil {
		t.Fatal("missing prefixes unexpectedly accepted")
	}
}

func TestWritePrefixFileProtectsLargeCountDrop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "as64500.txt")
	if err := os.WriteFile(path, []byte("2001:db8:1::/48\n2001:db8:2::/48\n2001:db8:3::/48\n2001:db8:4::/48\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := writePrefixFile(path, []string{"2001:db8:1::/48"})
	if !errors.Is(err, errPrefixCountDrop) {
		t.Fatalf("count drop error = %v", err)
	}
}
