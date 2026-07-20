package bgptools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const (
	defaultIPv4BootstrapURL   = "https://data.iana.org/rdap/ipv4.json"
	defaultIPv6BootstrapURL   = "https://data.iana.org/rdap/ipv6.json"
	defaultWHOISBootstrapSize = 4 << 20
)

var errWHOISBootstrapMissing = errors.New("IANA bootstrap has no WHOIS service for IP")

// resolveWHOISServer uses the IANA RDAP bootstrap only to identify the
// responsible RIR. The actual fallback remains a bounded port-43 query.
func resolveWHOISServer(ctx context.Context, ip string, cfg IPBGPReportConfig) (string, error) {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return "", ErrInvalidIPAddress
	}
	bootstrapURL := strings.TrimSpace(cfg.WHOISBootstrapURL)
	if bootstrapURL == "" {
		bootstrapURL = defaultIPv6BootstrapURL
		if parsed.To4() != nil {
			bootstrapURL = defaultIPv4BootstrapURL
		}
	}
	client := cfg.WHOISBootstrapClient
	if client == nil {
		client = cfg.RDAPClient
	}
	if client == nil {
		client = &http.Client{}
	}
	maximum := cfg.MaxWHOISBootstrapBytes
	if maximum <= 0 {
		maximum = defaultWHOISBootstrapSize
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bootstrapURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "oneclickvirt-backtrace-whois-bootstrap/1")
	response, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IANA bootstrap HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return "", err
	}
	if int64(len(body)) > maximum {
		return "", fmt.Errorf("IANA bootstrap response exceeds %d bytes", maximum)
	}
	var payload struct {
		Services [][][]string `json:"services"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", err
	}

	bestPrefix := -1
	bestServer := ""
	for _, service := range payload.Services {
		if len(service) < 2 {
			continue
		}
		server := whoisServerForRDAPURLs(service[1])
		if server == "" {
			continue
		}
		for _, prefix := range service[0] {
			_, network, err := net.ParseCIDR(strings.TrimSpace(prefix))
			if err != nil || !network.Contains(parsed) {
				continue
			}
			ones, _ := network.Mask.Size()
			if ones > bestPrefix {
				bestPrefix = ones
				bestServer = server
			}
		}
	}
	if bestServer == "" {
		return "", errWHOISBootstrapMissing
	}
	return bestServer, nil
}

func whoisServerForRDAPURLs(values []string) string {
	for _, value := range values {
		parsed, err := url.Parse(strings.TrimSpace(value))
		if err != nil {
			continue
		}
		host := strings.ToLower(parsed.Hostname())
		switch {
		case strings.Contains(host, "arin.net"):
			return "whois.arin.net"
		case strings.Contains(host, "apnic.net"):
			return "whois.apnic.net"
		case strings.Contains(host, "ripe.net"):
			return "whois.ripe.net"
		case strings.Contains(host, "afrinic.net"):
			return "whois.afrinic.net"
		case strings.Contains(host, "lacnic.net"):
			return "whois.lacnic.net"
		}
	}
	return ""
}
