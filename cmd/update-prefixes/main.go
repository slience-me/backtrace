package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var knownASNs = []string{"AS23764", "AS4134", "AS4809", "AS4837", "AS58453", "AS58807", "AS9808", "AS9929"}
var errPrefixCountDrop = errors.New("prefix count dropped beyond protection threshold")

type updateConfig struct {
	SourceBase string
	OutputDir  string
	Timeout    time.Duration
}

func main() {
	config := updateConfig{}
	flag.StringVar(&config.SourceBase, "source-base", "https://stat.ripe.net/data/announced-prefixes/data.json", "upstream announced-prefixes API")
	flag.StringVar(&config.OutputDir, "output-dir", "bk/prefix", "prefix snapshot directory")
	flag.DurationVar(&config.Timeout, "timeout", 30*time.Second, "upstream request timeout")
	flag.Parse()
	if err := updatePrefixes(context.Background(), http.DefaultClient, config); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func updatePrefixes(ctx context.Context, client *http.Client, config updateConfig) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if client == nil {
		client = http.DefaultClient
	}
	if config.SourceBase == "" || config.OutputDir == "" || config.Timeout <= 0 {
		return errors.New("source-base, output-dir, and timeout must be valid")
	}
	valuesByASN := make(map[string][]string, len(knownASNs))
	for _, asn := range knownASNs {
		requestCtx, cancel := context.WithTimeout(ctx, config.Timeout)
		endpoint, err := url.Parse(config.SourceBase)
		if err != nil {
			cancel()
			return fmt.Errorf("parse source URL: %w", err)
		}
		query := endpoint.Query()
		query.Set("resource", asn)
		endpoint.RawQuery = query.Encode()
		request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint.String(), nil)
		if err != nil {
			cancel()
			return err
		}
		request.Header.Set("User-Agent", "oneclickvirt-backtrace-prefix-sync/1")
		response, err := client.Do(request)
		if err != nil {
			cancel()
			return fmt.Errorf("fetch %s: %w", asn, err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 8<<20))
		response.Body.Close()
		cancel()
		if readErr != nil {
			return readErr
		}
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("fetch %s: HTTP %d", asn, response.StatusCode)
		}
		values, err := extractIPv6Prefixes(body)
		if err != nil {
			return fmt.Errorf("parse %s: %w", asn, err)
		}
		valuesByASN[asn] = values
	}
	for _, asn := range knownASNs {
		if err := writePrefixFile(filepath.Join(config.OutputDir, strings.ToLower(asn)+".txt"), valuesByASN[asn]); err != nil {
			if errors.Is(err, errPrefixCountDrop) {
				fmt.Fprintf(os.Stderr, "skip %s: %v\n", asn, err)
				continue
			}
			return err
		}
	}
	return nil
}

func extractIPv6Prefixes(data []byte) ([]string, error) {
	var response struct {
		Status string `json:"status"`
		Data   struct {
			Resource string `json:"resource"`
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, fmt.Errorf("decode announced-prefixes response: %w", err)
	}
	if response.Status != "ok" || response.Data.Resource == "" || response.Data.Prefixes == nil {
		return nil, errors.New("announced-prefixes response is missing required fields")
	}
	seen := make(map[string]struct{})
	for _, record := range response.Data.Prefixes {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(record.Prefix))
		if err != nil || !prefix.Addr().Is6() || prefix.Bits() < 16 || prefix.Bits() > 128 {
			continue
		}
		seen[prefix.String()] = struct{}{}
	}
	values := make([]string, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	sort.Strings(values)
	if len(values) == 0 {
		return nil, errors.New("no IPv6 prefixes found")
	}
	return values, nil
}

func writePrefixFile(output string, values []string) error {
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return err
	}
	candidate := []byte(strings.Join(values, "\n") + "\n")
	current, readErr := os.ReadFile(output)
	if readErr == nil {
		currentCount := countNonemptyLines(current)
		if currentCount > 0 && len(values)*100 < currentCount*65 {
			return fmt.Errorf("%w: prefix count dropped from %d to %d for %s", errPrefixCountDrop, currentCount, len(values), filepath.Base(output))
		}
		if bytes.Equal(current, candidate) {
			return nil
		}
	}
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	temporary, err := os.CreateTemp(filepath.Dir(output), ".prefix-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(candidate); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, output)
}

func countNonemptyLines(data []byte) int {
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}
