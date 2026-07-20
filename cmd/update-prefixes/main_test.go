package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

func TestWritePrefixManifestPreservesGeneratedAtWhenSnapshotIsUnchanged(t *testing.T) {
	directory := t.TempDir()
	snapshotPath := filepath.Join(directory, "as64500.txt")
	if err := os.WriteFile(snapshotPath, []byte("2001:db8::/48\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifestPath := snapshotPath + ".manifest.json"
	old := prefixManifest{Schema: "backtrace.asn-prefixes/v1", File: "as64500.txt", Count: 1, SHA256: "", GeneratedAt: "2020-01-02T03:04:05Z"}
	data, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	// Seed a valid manifest with an old timestamp. The updater must retain it.
	hash := sha256.Sum256(data)
	old.SHA256 = hex.EncodeToString(hash[:])
	encoded, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writePrefixManifest(snapshotPath); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(actual, []byte(`"generated_at":"2020-01-02T03:04:05Z"`)) {
		t.Fatalf("generated_at was not preserved: %s", actual)
	}
}
