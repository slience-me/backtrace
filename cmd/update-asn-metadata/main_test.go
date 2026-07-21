package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oneclickvirt/backtrace/bgptools"
)

func TestParseEntriesDeduplicatesAndSorts(t *testing.T) {
	entries, err := parseEntries(strings.NewReader("AS3356 Lumen\nAS174 Cogent\nAS3356 Level3\ninvalid\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0] != (bgptools.ASNMetadata{ASN: 174, Name: "Cogent"}) || entries[1].Name != "Lumen" {
		t.Fatalf("unexpected entries: %#v", entries)
	}
}

func TestUpdateSnapshotRejectsCountDrop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "asn.json")
	current := `{"schema":"backtrace.asn-metadata/v1","generated_at":"2026-07-20T00:00:00Z","entries":[{"asn":1,"name":"One"},{"asn":2,"name":"Two"}]}`
	if err := os.WriteFile(path, []byte(current), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := updateSnapshot(path, []bgptools.ASNMetadata{{ASN: 1, Name: "One"}}, 1); err == nil {
		t.Fatal("count drop unexpectedly accepted")
	}
}
