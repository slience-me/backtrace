package backtrace

import (
	"context"
	_ "embed"
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
	ASNPrefixRegistryRawBaseURL = "https://raw.githubusercontent.com/oneclickvirt/backtrace/main/bk/prefix"
	ASNPrefixRegistryCDNBaseURL = "https://cdn.spiritlhl.net/" + ASNPrefixRegistryRawBaseURL
)

var knownPrefixASNs = []string{"AS23764", "AS4134", "AS4809", "AS4837", "AS58453", "AS58807", "AS9808", "AS9929"}
var prefixFragmentPattern = regexp.MustCompile(`^[0-9a-fA-F:]+$`)

type ASNPrefixRegistrySource struct {
	Name string
	Base string
}

type ASNPrefixRegistryLoadResult struct {
	Prefixes map[string][]string
	Source   string
	Fallback bool
}

var activeASNPrefixes atomic.Value // stores map[string][]string; maps are immutable after publication
var refreshASNPrefixesOnce sync.Once

func init() {
	activeASNPrefixes.Store(cloneASNPrefixes(asnPrefixes))
}

func DefaultASNPrefixRegistrySources() []ASNPrefixRegistrySource {
	return []ASNPrefixRegistrySource{
		{Name: "cdn", Base: ASNPrefixRegistryCDNBaseURL},
		{Name: "raw", Base: ASNPrefixRegistryRawBaseURL},
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
		prefixes, err := fetchASNPrefixSource(ctx, client, source.Base)
		if err != nil {
			lastErr = fmt.Errorf("load %s ASN prefixes: %w", source.Name, err)
			continue
		}
		return ASNPrefixRegistryLoadResult{Prefixes: prefixes, Source: source.Name, Fallback: index > 0}, nil
	}
	embedded := cloneASNPrefixes(asnPrefixes)
	if len(embedded) > 0 {
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

func fetchASNPrefixSource(ctx context.Context, client *http.Client, base string) (map[string][]string, error) {
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
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
			if err != nil {
				results <- prefixResult{asn: asn, err: err}
				return
			}
			request.Header.Set("Accept", "text/plain")
			request.Header.Set("User-Agent", "oneclickvirt-backtrace/asn-prefix-registry-v1")
			response, err := client.Do(request)
			if err != nil {
				results <- prefixResult{asn: asn, err: err}
				return
			}
			data, readErr := io.ReadAll(io.LimitReader(response.Body, 4<<20))
			response.Body.Close()
			if readErr != nil {
				results <- prefixResult{asn: asn, err: readErr}
				return
			}
			if response.StatusCode != http.StatusOK {
				results <- prefixResult{asn: asn, err: fmt.Errorf("HTTP %d", response.StatusCode)}
				return
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
