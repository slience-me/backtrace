package backtrace

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ASNPrefixRegistrySchema     = "backtrace.asn-prefixes/v1"
	ASNPrefixRegistryRawBaseURL = "https://raw.githubusercontent.com/oneclickvirt/backtrace/main/bk/prefix"
	ASNPrefixRegistryCDNBaseURL = "https://cdn.spiritlhl.net/" + ASNPrefixRegistryRawBaseURL
)

var knownPrefixASNs = []string{"AS23764", "AS4134", "AS4809", "AS4837", "AS58453", "AS58807", "AS9808", "AS9929"}
var prefixFragmentPattern = regexp.MustCompile(`^[0-9a-fA-F:]+$`)

type ASNPrefixRegistrySource struct {
	Name             string
	Base             string
	ValidateManifest bool
}

type ASNPrefixRegistryLoadResult struct {
	Prefixes map[string][]string
	Source   string
	Fallback bool
}

var activeASNPrefixes atomic.Value // stores map[string][]string; maps are immutable after publication
var refreshASNPrefixesOnce sync.Once

//go:embed prefix/*.txt.manifest.json
var embeddedPrefixManifestFS embed.FS

func init() {
	activeASNPrefixes.Store(cloneASNPrefixes(asnPrefixes))
}

func DefaultASNPrefixRegistrySources() []ASNPrefixRegistrySource {
	return []ASNPrefixRegistrySource{
		{Name: "cdn", Base: ASNPrefixRegistryCDNBaseURL, ValidateManifest: true},
		{Name: "raw", Base: ASNPrefixRegistryRawBaseURL, ValidateManifest: true},
	}
}

func LoadASNPrefixRegistry(ctx context.Context, client *http.Client, sources []ASNPrefixRegistrySource) (ASNPrefixRegistryLoadResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if client == nil {
		client = &http.Client{Timeout: 6 * time.Second}
	}
	var lastErr error
	for index, source := range sources {
		prefixes, err := fetchASNPrefixSource(ctx, client, source)
		if err != nil {
			lastErr = fmt.Errorf("load %s ASN prefixes: %w", source.Name, err)
			continue
		}
		return ASNPrefixRegistryLoadResult{Prefixes: prefixes, Source: source.Name, Fallback: index > 0}, nil
	}
	embedded := cloneASNPrefixes(asnPrefixes)
	if len(embedded) > 0 {
		if err := validateEmbeddedPrefixManifests(); err != nil {
			return ASNPrefixRegistryLoadResult{}, fmt.Errorf("validate embedded ASN prefix manifests: %w", err)
		}
		return ASNPrefixRegistryLoadResult{Prefixes: embedded, Source: "embedded", Fallback: true}, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no ASN prefix registry sources configured")
	}
	return ASNPrefixRegistryLoadResult{}, lastErr
}

func RefreshASNPrefixRegistry(ctx context.Context, client *http.Client, sources []ASNPrefixRegistrySource) (ASNPrefixRegistryLoadResult, error) {
	loaded, err := LoadASNPrefixRegistry(ctx, client, sources)
	if err != nil {
		return ASNPrefixRegistryLoadResult{}, err
	}
	activeASNPrefixes.Store(cloneASNPrefixes(loaded.Prefixes))
	return loaded, nil
}

// StartASNPrefixRefresh performs one bounded background refresh. It never
// delays legacy tracing and the embedded map remains active on any error.
func StartASNPrefixRefresh() {
	refreshASNPrefixesOnce.Do(func() {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_, _ = RefreshASNPrefixRegistry(ctx, nil, DefaultASNPrefixRegistrySources())
		}()
	})
}

type prefixManifest struct {
	Schema      string `json:"schema"`
	File        string `json:"file"`
	Count       int    `json:"count"`
	SHA256      string `json:"sha256"`
	GeneratedAt string `json:"generated_at"`
}

func fetchASNPrefixSource(ctx context.Context, client *http.Client, source ASNPrefixRegistrySource) (map[string][]string, error) {
	base := source.Base
	parsed, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return nil, errors.New("invalid ASN prefix source")
	}
	type prefixResult struct {
		asn    string
		values []string
		err    error
	}
	results := make(chan prefixResult, len(knownPrefixASNs))
	for _, asn := range knownPrefixASNs {
		go func(asn string) {
			endpoint := strings.TrimRight(base, "/") + "/" + strings.ToLower(asn) + ".txt"
			var manifestData []byte
			if source.ValidateManifest {
				fetchedManifest, fetchErr := fetchPrefixResource(ctx, client, endpoint+".manifest.json")
				if fetchErr != nil {
					results <- prefixResult{asn: asn, err: fmt.Errorf("manifest: %w", fetchErr)}
					return
				}
				manifestData = fetchedManifest
			}
			data, err := fetchPrefixResource(ctx, client, endpoint)
			if err != nil {
				results <- prefixResult{asn: asn, err: err}
				return
			}
			if source.ValidateManifest {
				if err := validatePrefixManifest(manifestData, data, strings.ToLower(asn)+".txt"); err != nil {
					results <- prefixResult{asn: asn, err: err}
					return
				}
			}
			values, parseErr := parseASNPrefixLines(data)
			results <- prefixResult{asn: asn, values: values, err: parseErr}
		}(asn)
	}
	result := make(map[string][]string, len(knownPrefixASNs))
	for range knownPrefixASNs {
		loaded := <-results
		if loaded.err != nil {
			return nil, fmt.Errorf("%s: %w", loaded.asn, loaded.err)
		}
		result[loaded.asn] = loaded.values
	}
	return result, nil
}

func fetchPrefixResource(ctx context.Context, client *http.Client, endpoint string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "text/plain, application/json")
	request.Header.Set("User-Agent", "oneclickvirt-backtrace/asn-prefix-registry-v1")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	return io.ReadAll(io.LimitReader(response.Body, 4<<20))
}

func validatePrefixManifest(data, snapshot []byte, expectedFile string) error {
	var manifest prefixManifest
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return fmt.Errorf("decode manifest: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("manifest contains trailing JSON")
	}
	if manifest.Schema != ASNPrefixRegistrySchema || manifest.File != expectedFile || manifest.Count < 1 {
		return errors.New("manifest schema, file, or count is invalid")
	}
	if _, err := time.Parse(time.RFC3339, manifest.GeneratedAt); err != nil {
		return fmt.Errorf("manifest generated_at is invalid: %w", err)
	}
	hash := sha256.Sum256(snapshot)
	if !strings.EqualFold(manifest.SHA256, hex.EncodeToString(hash[:])) {
		return errors.New("manifest SHA-256 does not match snapshot")
	}
	values, err := parseASNPrefixLines(snapshot)
	if err != nil {
		return err
	}
	if len(values) != manifest.Count {
		return fmt.Errorf("manifest count %d does not match snapshot count %d", manifest.Count, len(values))
	}
	return nil
}

func validateEmbeddedPrefixManifests() error {
	for _, asn := range knownPrefixASNs {
		name := strings.ToLower(asn) + ".txt"
		manifest, err := embeddedPrefixManifestFS.ReadFile("prefix/" + name + ".manifest.json")
		if err != nil {
			return err
		}
		var snapshot []byte
		switch asn {
		case "AS23764":
			snapshot = []byte(as23764Data)
		case "AS4134":
			snapshot = []byte(as4134Data)
		case "AS4809":
			snapshot = []byte(as4809Data)
		case "AS4837":
			snapshot = []byte(as4837Data)
		case "AS58453":
			snapshot = []byte(as58453Data)
		case "AS58807":
			snapshot = []byte(as58807Data)
		case "AS9808":
			snapshot = []byte(as9808Data)
		case "AS9929":
			snapshot = []byte(as9929Data)
		}
		if err := validatePrefixManifest(manifest, snapshot, name); err != nil {
			return fmt.Errorf("%s: %w", asn, err)
		}
	}
	return nil
}

func parseASNPrefixLines(data []byte) ([]string, error) {
	seen := make(map[string]struct{})
	values := make([]string, 0)
	for _, raw := range strings.Split(string(data), "\n") {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if strings.Contains(value, "/") {
			prefix, err := netip.ParsePrefix(value)
			if err != nil || !prefix.Addr().Is6() {
				return nil, fmt.Errorf("invalid IPv6 prefix %q", value)
			}
		} else if !prefixFragmentPattern.MatchString(value) {
			return nil, fmt.Errorf("invalid prefix fragment %q", value)
		}
		value = strings.ToLower(value)
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	if len(values) == 0 {
		return nil, errors.New("prefix file is empty")
	}
	sort.Strings(values)
	return values, nil
}

func cloneASNPrefixes(input map[string][]string) map[string][]string {
	result := make(map[string][]string, len(input))
	for asn, values := range input {
		result[asn] = append([]string(nil), values...)
	}
	return result
}

func currentASNPrefixes() map[string][]string {
	if value := activeASNPrefixes.Load(); value != nil {
		return value.(map[string][]string)
	}
	return asnPrefixes
}
