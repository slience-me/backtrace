package bgptools

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	ASNMetadataSchema  = "backtrace.asn-metadata/v1"
	ASNMetadataMinimum = 50
)

var asnMetadataSnapshotURLs = []string{
	"https://cdn.spiritlhl.net/https://raw.githubusercontent.com/oneclickvirt/backtrace/main/bgptools/data/bgp-asn-map.json",
	"https://raw.githubusercontent.com/oneclickvirt/backtrace/main/bgptools/data/bgp-asn-map.json",
}

//go:embed data/bgp-asn-map.json
var embeddedASNMetadata []byte

type ASNMetadata struct {
	ASN  uint32 `json:"asn"`
	Name string `json:"name"`
}

type ASNMetadataSource struct {
	Schema      string    `json:"schema"`
	Count       int       `json:"count"`
	GeneratedAt time.Time `json:"generated_at,omitempty"`
	Source      string    `json:"source"`
	Fallback    bool      `json:"fallback"`
}

type asnMetadataDocument struct {
	Schema      string        `json:"schema"`
	GeneratedAt time.Time     `json:"generated_at"`
	Entries     []ASNMetadata `json:"entries"`
}

// LoadASNMetadata prefers the component's validated remote snapshot and
// falls back to the compile-time snapshot. Upstream registry URLs and parsing
// rules are intentionally not exposed to callers.
func LoadASNMetadata(ctx context.Context, client *http.Client) ([]ASNMetadata, ASNMetadataSource, error) {
	return loadASNMetadata(ctx, client, asnMetadataSnapshotURLs, embeddedASNMetadata, ASNMetadataMinimum)
}

// EmbeddedASNMetadata returns the validated compile-time snapshot without
// performing network access.
func EmbeddedASNMetadata() ([]ASNMetadata, ASNMetadataSource, error) {
	entries, generatedAt, err := parseASNMetadataDocument(embeddedASNMetadata, ASNMetadataMinimum)
	if err != nil {
		return nil, ASNMetadataSource{}, err
	}
	return entries, ASNMetadataSource{Schema: ASNMetadataSchema, Count: len(entries), GeneratedAt: generatedAt, Source: "embedded", Fallback: true}, nil
}

// LookupASNMetadata resolves one ASN from the current component registry.
func LookupASNMetadata(ctx context.Context, client *http.Client, asn string) (ASNMetadata, ASNMetadataSource, bool, error) {
	normalized, err := normalizeASN(asn)
	if err != nil {
		return ASNMetadata{}, ASNMetadataSource{}, false, err
	}
	number, _ := strconv.ParseUint(normalized, 10, 32)
	entries, source, err := LoadASNMetadata(ctx, client)
	if err != nil {
		return ASNMetadata{}, ASNMetadataSource{}, false, err
	}
	index := sort.Search(len(entries), func(index int) bool { return entries[index].ASN >= uint32(number) })
	if index >= len(entries) || entries[index].ASN != uint32(number) {
		return ASNMetadata{}, source, false, nil
	}
	return entries[index], source, true, nil
}

func loadASNMetadata(ctx context.Context, client *http.Client, urls []string, embedded []byte, minimum int) ([]ASNMetadata, ASNMetadataSource, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	embeddedEntries, embeddedAt, err := parseASNMetadataDocument(embedded, minimum)
	if err != nil {
		return nil, ASNMetadataSource{}, fmt.Errorf("invalid embedded ASN metadata: %w", err)
	}
	if client == nil {
		client = &http.Client{Timeout: 6 * time.Second}
	}
	minimumRemote := max(minimum, len(embeddedEntries)*65/100)
	for _, snapshotURL := range urls {
		data, fetchErr := fetchASNMetadata(ctx, client, snapshotURL)
		if fetchErr != nil {
			continue
		}
		entries, generatedAt, parseErr := parseASNMetadataDocument(data, minimumRemote)
		if parseErr == nil {
			return entries, ASNMetadataSource{Schema: ASNMetadataSchema, Count: len(entries), GeneratedAt: generatedAt, Source: "remote"}, nil
		}
	}
	return embeddedEntries, ASNMetadataSource{Schema: ASNMetadataSchema, Count: len(embeddedEntries), GeneratedAt: embeddedAt, Source: "embedded", Fallback: true}, nil
}

func fetchASNMetadata(ctx context.Context, client *http.Client, snapshotURL string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, snapshotURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "oneclickvirt-backtrace-asn-metadata/1")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	const maximumSize = 4 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, maximumSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maximumSize {
		return nil, fmt.Errorf("ASN metadata exceeds %d bytes", maximumSize)
	}
	return data, nil
}

func parseASNMetadataDocument(data []byte, minimum int) ([]ASNMetadata, time.Time, error) {
	var document asnMetadataDocument
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, time.Time{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, time.Time{}, errors.New("ASN metadata contains trailing JSON")
	}
	if document.Schema != ASNMetadataSchema || document.GeneratedAt.IsZero() {
		return nil, time.Time{}, errors.New("ASN metadata schema or generated_at is invalid")
	}
	seen := make(map[uint32]struct{}, len(document.Entries))
	entries := make([]ASNMetadata, 0, len(document.Entries))
	for _, entry := range document.Entries {
		entry.Name = strings.TrimSpace(entry.Name)
		if entry.ASN == 0 || entry.Name == "" {
			return nil, time.Time{}, errors.New("ASN metadata contains an invalid entry")
		}
		if _, exists := seen[entry.ASN]; exists {
			return nil, time.Time{}, fmt.Errorf("ASN metadata contains duplicate AS%d", entry.ASN)
		}
		seen[entry.ASN] = struct{}{}
		entries = append(entries, entry)
	}
	if len(entries) < minimum {
		return nil, time.Time{}, fmt.Errorf("ASN metadata count %d is below minimum %d", len(entries), minimum)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ASN < entries[j].ASN })
	return entries, document.GeneratedAt, nil
}
