package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/oneclickvirt/backtrace/bgptools"
)

const defaultSource = "https://raw.githubusercontent.com/xykt/NetQuality/main/ref/AS_Mapping.txt"

type document struct {
	Schema      string                 `json:"schema"`
	GeneratedAt time.Time              `json:"generated_at"`
	Entries     []bgptools.ASNMetadata `json:"entries"`
}

func main() {
	source := flag.String("source", defaultSource, "ASN name registry URL")
	output := flag.String("output", "bgptools/data/bgp-asn-map.json", "snapshot output path")
	minimum := flag.Int("min-count", bgptools.ASNMetadataMinimum, "minimum accepted ASN count")
	timeout := flag.Duration("timeout", 30*time.Second, "fetch timeout")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	entries, err := fetchEntries(ctx, http.DefaultClient, *source)
	if err != nil {
		fatal(err)
	}
	if err := updateSnapshot(*output, entries, *minimum); err != nil {
		fatal(err)
	}
}

func fetchEntries(ctx context.Context, client *http.Client, source string) ([]bgptools.ASNMetadata, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "oneclickvirt-backtrace-asn-sync/1")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ASN registry returned HTTP %d", response.StatusCode)
	}
	return parseEntries(io.LimitReader(response.Body, 4<<20))
}

func parseEntries(reader io.Reader) ([]bgptools.ASNMetadata, error) {
	seen := make(map[uint32]string)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || !strings.HasPrefix(strings.ToUpper(fields[0]), "AS") {
			continue
		}
		number, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(fields[0]), "AS"), 10, 32)
		if err != nil || number == 0 {
			continue
		}
		if _, exists := seen[uint32(number)]; !exists {
			seen[uint32(number)] = strings.Join(fields[1:], " ")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	entries := make([]bgptools.ASNMetadata, 0, len(seen))
	for asn, name := range seen {
		entries = append(entries, bgptools.ASNMetadata{ASN: asn, Name: name})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ASN < entries[j].ASN })
	if len(entries) == 0 {
		return nil, fmt.Errorf("ASN registry contains no valid entries")
	}
	return entries, nil
}

func updateSnapshot(path string, entries []bgptools.ASNMetadata, minimum int) error {
	if len(entries) < minimum {
		return fmt.Errorf("ASN count %d is below minimum %d", len(entries), minimum)
	}
	currentData, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var current document
	if err := json.Unmarshal(currentData, &current); err != nil || current.Schema != bgptools.ASNMetadataSchema {
		return fmt.Errorf("current ASN metadata schema is invalid")
	}
	if len(current.Entries) >= minimum && len(entries)*100 < len(current.Entries)*65 {
		return fmt.Errorf("ASN count dropped from %d to %d", len(current.Entries), len(entries))
	}
	if sameEntries(current.Entries, entries) && !current.GeneratedAt.IsZero() {
		return nil
	}
	next, err := json.MarshalIndent(document{Schema: bgptools.ASNMetadataSchema, GeneratedAt: time.Now().UTC(), Entries: entries}, "", "  ")
	if err != nil {
		return err
	}
	next = append(next, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(path), ".asn-metadata-*.json")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if _, err := temporary.Write(next); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func sameEntries(left, right []bgptools.ASNMetadata) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
