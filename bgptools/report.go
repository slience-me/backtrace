package bgptools

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// ReportStatus is the provider-neutral status used by the unified IP/BGP
// report.  A report deliberately keeps source-level failures instead of
// turning them into an empty successful result.
type ReportStatus string

const (
	ReportAvailable     ReportStatus = "available"
	ReportPartial       ReportStatus = "partial"
	ReportRateLimited   ReportStatus = "rate_limited"
	ReportTimeout       ReportStatus = "timeout"
	ReportMissingFields ReportStatus = "missing_fields"
	ReportError         ReportStatus = "error"
	ReportUnsupported   ReportStatus = "unsupported"
)

// IPBGPSourceStatus records the outcome of one logical source in a unified
// report.  Error is intentionally a short diagnostic, never a raw response.
type IPBGPSourceStatus struct {
	Source string       `json:"source"`
	Status ReportStatus `json:"status"`
	Error  string       `json:"error,omitempty"`
}

// RIRInfo describes the registry inference and its evidence source.  The
// inference is conservative: country and address ownership are not used as a
// substitute for an explicit RDAP/WHOIS registry signal.
type RIRInfo struct {
	Name   string       `json:"name,omitempty"`
	Source string       `json:"source,omitempty"`
	Status ReportStatus `json:"status"`
}

// GeofeedResult contains an RDAP/WHOIS geofeed URL and, when requested, the
// bounded fetch result.  The payload itself is not retained in the report.
type GeofeedResult struct {
	URL        string       `json:"url"`
	Status     ReportStatus `json:"status"`
	HTTPStatus int          `json:"http_status,omitempty"`
	Bytes      int64        `json:"bytes,omitempty"`
	Error      string       `json:"error,omitempty"`
}

// WHOISRecord is the small, structured subset used when RDAP is unavailable
// or missing required fields.  Raw port-43 text is never returned.
type WHOISRecord struct {
	Server           string       `json:"server"`
	Status           ReportStatus `json:"status"`
	Prefixes         []string     `json:"prefixes,omitempty"`
	RegistrationDate *time.Time   `json:"registration_date,omitempty"`
	GeofeedURLs      []string     `json:"geofeed_urls,omitempty"`
	RIR              RIRInfo      `json:"rir"`
}

// IPBGPReport combines RDAP, registry metadata, optional geofeed fetches and
// ASN relationship data.  Relationships are requested only when ASN or an
// injected ASN resolver supplies a target ASN.
type IPBGPReport struct {
	IP               string                 `json:"ip"`
	ASN              string                 `json:"asn,omitempty"`
	Status           ReportStatus           `json:"status"`
	RDAP             *RDAPRecord            `json:"rdap,omitempty"`
	WHOIS            *WHOISRecord           `json:"whois,omitempty"`
	Prefixes         []string               `json:"prefixes,omitempty"`
	PrefixSource     string                 `json:"prefix_source,omitempty"`
	RegistrationDate *time.Time             `json:"registration_date,omitempty"`
	RIR              RIRInfo                `json:"rir"`
	Geofeeds         []GeofeedResult        `json:"geofeeds,omitempty"`
	Relationships    *ASNRelationshipReport `json:"relationships,omitempty"`
	Sources          []IPBGPSourceStatus    `json:"sources"`
}

// ASNResolver allows a caller to supply an existing, structured IP-to-ASN
// result without making this package invent a provider or read environment
// variables.
type ASNResolver func(context.Context, string) (string, error)

// WHOISDialContext is injectable so port-43 fallback can be tested entirely
// with a local TCP fixture.
type WHOISDialContext func(context.Context, string, string) (net.Conn, error)

// IPBGPReportConfig keeps every network dependency explicit and injectable.
// WHOIS fallback is opt-in; when enabled it always has its own finite timeout.
type IPBGPReportConfig struct {
	Timeout time.Duration

	RDAPClient  *http.Client
	RDAPBaseURL string

	ASN           string
	ResolveASN    ASNResolver
	Relationships RelationshipConfig

	FetchGeofeed    bool
	GeofeedClient   *http.Client
	GeofeedTimeout  time.Duration
	MaxGeofeedBytes int64

	EnableWHOISFallback bool
	WHOISServer         string
	WHOISTimeout        time.Duration
	MaxWHOISBytes       int64
	WHOISDialContext    WHOISDialContext

	WHOISBootstrapClient   *http.Client
	WHOISBootstrapURL      string
	MaxWHOISBootstrapBytes int64
}

const (
	defaultIPBGPReportTimeout = 15 * time.Second
	defaultGeofeedTimeout     = 3 * time.Second
	defaultWHOISTimeout       = 3 * time.Second
	defaultGeofeedBytes       = 1 << 20
	defaultWHOISBytes         = 1 << 20
)

// QueryIPBGPReport executes the structured IP/BGP collection with a bounded
// context.  Provider failures produce a partial report; invalid input and
// caller cancellation are returned as errors for compatibility with the
// lower-level APIs.
func QueryIPBGPReport(parent context.Context, ip string, cfg IPBGPReportConfig) (*IPBGPReport, error) {
	if parent == nil {
		parent = context.Background()
	}
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return nil, ErrInvalidIPAddress
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultIPBGPReportTimeout
	}
	ctx, cancel := context.WithTimeout(parent, cfg.Timeout)
	defer cancel()

	report := &IPBGPReport{IP: parsed.String(), Status: ReportError}

	rdap, rdapErr := QueryRDAP(ctx, report.IP, cfg.RDAPClient, cfg.RDAPBaseURL)
	rdapStatus := reportStatusForError(rdapErr)
	if rdapErr == nil {
		report.RDAP = &rdap
		report.Prefixes = uniqueSortedStrings(rdap.Prefixes)
		if len(report.Prefixes) > 0 {
			report.PrefixSource = "rdap"
		}
		report.RegistrationDate = rdap.RegistrationDate
		rdapStatus = ReportAvailable
		if len(report.Prefixes) == 0 || report.RegistrationDate == nil {
			rdapStatus = ReportMissingFields
		}
		report.Sources = append(report.Sources, IPBGPSourceStatus{Source: "rdap", Status: rdapStatus})
	} else {
		report.Sources = append(report.Sources, sourceStatusForError("rdap", rdapStatus, rdapErr))
	}

	report.RIR = inferRIR(rdap, rdapErr == nil)
	if report.RIR.Status == "" {
		report.RIR.Status = ReportMissingFields
	}

	if cfg.EnableWHOISFallback && (rdapErr != nil || len(report.Prefixes) == 0 || report.RegistrationDate == nil || report.RIR.Status != ReportAvailable) {
		server := strings.TrimSpace(cfg.WHOISServer)
		if server == "" {
			server = strings.TrimSpace(rdap.Port43)
		}
		if server == "" {
			resolved, err := resolveWHOISServer(ctx, report.IP, cfg)
			if err != nil {
				report.Sources = append(report.Sources, sourceStatusForError("whois_bootstrap", reportStatusForError(err), err))
			} else {
				server = resolved
				report.Sources = append(report.Sources, IPBGPSourceStatus{Source: "whois_bootstrap", Status: ReportAvailable})
			}
		}
		if server == "" {
			status := IPBGPSourceStatus{Source: "whois", Status: ReportUnsupported, Error: "no port-43 server resolved"}
			report.Sources = append(report.Sources, status)
		} else {
			whois, err := queryWHOIS(ctx, report.IP, server, cfg)
			if err != nil {
				report.Sources = append(report.Sources, sourceStatusForError("whois", reportStatusForError(err), err))
			} else {
				report.WHOIS = &whois
				report.Sources = append(report.Sources, IPBGPSourceStatus{Source: "whois", Status: whois.Status})
				if len(report.Prefixes) == 0 && len(whois.Prefixes) > 0 {
					report.Prefixes = append([]string(nil), whois.Prefixes...)
					report.PrefixSource = "whois"
				}
				if report.RegistrationDate == nil {
					report.RegistrationDate = whois.RegistrationDate
				}
				if report.RIR.Status != ReportAvailable && whois.RIR.Status == ReportAvailable {
					report.RIR = whois.RIR
				}
			}
		}
	}
	report.Sources = append(report.Sources, IPBGPSourceStatus{Source: "rir", Status: report.RIR.Status})

	geofeedURLs := append([]string(nil), rdap.GeofeedURLs...)
	if report.WHOIS != nil {
		geofeedURLs = append(geofeedURLs, report.WHOIS.GeofeedURLs...)
	}
	geofeedURLs = uniqueSortedStrings(geofeedURLs)
	if report.RDAP != nil {
		report.RDAP.GeofeedURLs = sanitizeReportURLs(report.RDAP.GeofeedURLs)
	}
	if report.WHOIS != nil {
		report.WHOIS.GeofeedURLs = sanitizeReportURLs(report.WHOIS.GeofeedURLs)
	}
	for _, geofeedURL := range geofeedURLs {
		if !cfg.FetchGeofeed {
			report.Geofeeds = append(report.Geofeeds, GeofeedResult{URL: geofeedURL, Status: ReportUnsupported, Error: "fetch disabled"})
			continue
		}
		result := fetchGeofeed(ctx, geofeedURL, cfg)
		report.Geofeeds = append(report.Geofeeds, result)
		report.Sources = append(report.Sources, IPBGPSourceStatus{Source: "geofeed", Status: result.Status, Error: result.Error})
	}

	asn := strings.TrimSpace(cfg.ASN)
	if asn == "" && cfg.ResolveASN != nil {
		resolved, err := cfg.ResolveASN(ctx, report.IP)
		if err != nil {
			report.Sources = append(report.Sources, sourceStatusForError("asn_resolver", reportStatusForError(err), err))
		} else {
			asn = strings.TrimSpace(resolved)
			report.Sources = append(report.Sources, IPBGPSourceStatus{Source: "asn_resolver", Status: ReportAvailable})
		}
	}
	if asn != "" {
		normalizedASN, err := normalizeASN(asn)
		if err != nil {
			return report, err
		}
		report.ASN = normalizedASN
		relationships, err := QueryASNRelationships(ctx, normalizedASN, cfg.Relationships)
		if relationships != nil {
			report.Relationships = relationships
		}
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return report, err
			}
			report.Sources = append(report.Sources, sourceStatusForError("asn_relationships", reportStatusForError(err), err))
		} else {
			report.Sources = append(report.Sources, IPBGPSourceStatus{Source: "asn_relationships", Status: reportStatusFromRelationship(relationships.Status)})
		}
	} else {
		report.Sources = append(report.Sources, IPBGPSourceStatus{Source: "asn_relationships", Status: ReportUnsupported, Error: "ASN not supplied"})
	}

	if err := ctx.Err(); err != nil {
		return report, err
	}
	report.Prefixes = uniqueSortedStrings(report.Prefixes)
	sort.SliceStable(report.Sources, func(i, j int) bool { return report.Sources[i].Source < report.Sources[j].Source })
	report.Status = aggregateReportStatus(report.Sources)
	return report, nil
}

// QueryIPBGP is a short alias for callers that prefer the domain name over the
// implementation-oriented Report suffix.
func QueryIPBGP(ctx context.Context, ip string, cfg IPBGPReportConfig) (*IPBGPReport, error) {
	return QueryIPBGPReport(ctx, ip, cfg)
}

func inferRIR(record RDAPRecord, available bool) RIRInfo {
	if !available {
		return RIRInfo{Status: ReportMissingFields}
	}
	text := strings.Join([]string{record.Source, record.Port43, record.Handle, record.ParentHandle}, " ")
	if name := rirNameFromText(text); name != "" {
		return RIRInfo{Name: name, Source: "rdap", Status: ReportAvailable}
	}
	return RIRInfo{Source: "rdap", Status: ReportMissingFields}
}

func fetchGeofeed(parent context.Context, rawURL string, cfg IPBGPReportConfig) GeofeedResult {
	result := GeofeedResult{URL: sanitizeReportURL(rawURL)}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		result.Status = ReportUnsupported
		result.Error = "unsupported geofeed URL"
		return result
	}
	timeout := cfg.GeofeedTimeout
	if timeout <= 0 {
		timeout = defaultGeofeedTimeout
	}
	maxBytes := cfg.MaxGeofeedBytes
	if maxBytes <= 0 {
		maxBytes = defaultGeofeedBytes
	}
	client := cfg.GeofeedClient
	if client == nil {
		client = &http.Client{}
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		result.Status = ReportError
		result.Error = stableReportError(result.Status, err)
		return result
	}
	req.Header.Set("Accept", "text/csv, text/plain, */*")
	req.Header.Set("User-Agent", "oneclickvirt-backtrace-geofeed/1")
	resp, err := client.Do(req)
	if err != nil {
		result.Status = reportStatusForError(err)
		result.Error = stableReportError(result.Status, err)
		return result
	}
	defer resp.Body.Close()
	result.HTTPStatus = resp.StatusCode
	if resp.StatusCode == http.StatusTooManyRequests {
		result.Status = ReportRateLimited
		result.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return result
	}
	if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusGatewayTimeout {
		result.Status = ReportTimeout
		result.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return result
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		result.Status = ReportError
		result.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return result
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		result.Status = reportStatusForError(err)
		result.Error = stableReportError(result.Status, err)
		return result
	}
	if int64(len(body)) > maxBytes {
		result.Status = ReportError
		result.Error = fmt.Sprintf("response exceeds %d bytes", maxBytes)
		return result
	}
	result.Status = ReportAvailable
	result.Bytes = int64(len(body))
	return result
}

func queryWHOIS(parent context.Context, ip, server string, cfg IPBGPReportConfig) (WHOISRecord, error) {
	address, err := normalizeWHOISAddress(server)
	if err != nil {
		return WHOISRecord{}, err
	}
	timeout := cfg.WHOISTimeout
	if timeout <= 0 {
		timeout = defaultWHOISTimeout
	}
	maxBytes := cfg.MaxWHOISBytes
	if maxBytes <= 0 {
		maxBytes = defaultWHOISBytes
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	dial := cfg.WHOISDialContext
	if dial == nil {
		dialer := &net.Dialer{}
		dial = dialer.DialContext
	}
	conn, err := dial(ctx, "tcp", address)
	if err != nil {
		return WHOISRecord{}, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := fmt.Fprintf(conn, "%s\r\n", ip); err != nil {
		return WHOISRecord{}, err
	}
	body, err := io.ReadAll(io.LimitReader(conn, maxBytes+1))
	if err != nil {
		return WHOISRecord{}, err
	}
	if int64(len(body)) > maxBytes {
		return WHOISRecord{}, fmt.Errorf("whois response exceeds %d bytes", maxBytes)
	}
	result, err := parseWHOISRecord(address, body)
	if err != nil {
		return WHOISRecord{}, err
	}
	if len(result.Prefixes) == 0 && result.RegistrationDate == nil && result.RIR.Status != ReportAvailable && len(result.GeofeedURLs) == 0 {
		result.Status = ReportMissingFields
	} else {
		result.Status = ReportAvailable
	}
	return result, nil
}

func normalizeWHOISAddress(server string) (string, error) {
	server = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(server, "whois://"), "tcp://"))
	if server == "" || strings.ContainsAny(server, "/ \t\r\n") {
		return "", errors.New("invalid WHOIS server")
	}
	if host, port, err := net.SplitHostPort(server); err == nil {
		if host == "" || port == "" {
			return "", errors.New("invalid WHOIS server")
		}
		return net.JoinHostPort(host, port), nil
	}
	if strings.Contains(server, ":") && net.ParseIP(server) == nil {
		return "", errors.New("invalid WHOIS server")
	}
	return net.JoinHostPort(server, "43"), nil
}

func parseWHOISRecord(server string, body []byte) (WHOISRecord, error) {
	result := WHOISRecord{Server: server, RIR: RIRInfo{Status: ReportMissingFields}}
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	scanner.Buffer(make([]byte, 1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "cidr", "route", "route6", "inet6route", "prefix":
			for _, item := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\t' }) {
				if normalized, ok := normalizeWHOISPrefix(item); ok {
					result.Prefixes = append(result.Prefixes, normalized)
				}
			}
		case "registration date", "regdate", "created", "created date", "creation date":
			if parsed, ok := parseWHOISDate(value); ok {
				result.RegistrationDate = &parsed
			}
		case "geofeed", "geofeed url", "geofeed-url":
			if parsed, err := url.Parse(value); err == nil && parsed.Host != "" && (parsed.Scheme == "http" || parsed.Scheme == "https") {
				result.GeofeedURLs = append(result.GeofeedURLs, parsed.String())
			}
		case "rir", "registry", "source", "whois server":
			if name := rirNameFromText(value); name != "" {
				result.RIR = RIRInfo{Name: name, Source: "whois", Status: ReportAvailable}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return WHOISRecord{}, err
	}
	result.Prefixes = uniqueSortedStrings(result.Prefixes)
	result.GeofeedURLs = uniqueSortedStrings(result.GeofeedURLs)
	if result.RIR.Status != ReportAvailable {
		if name := rirNameFromText(server); name != "" {
			result.RIR = RIRInfo{Name: name, Source: "whois", Status: ReportAvailable}
		}
	}
	return result, nil
}

func normalizeWHOISPrefix(value string) (string, bool) {
	value = strings.TrimSpace(value)
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		return "", false
	}
	return network.String(), true
}

func parseWHOISDate(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02",
		"02-Jan-2006",
		"20060102",
	} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func rirNameFromText(value string) string {
	tokens := strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	})
	registries := map[string]string{
		"arin":    "ARIN",
		"ripe":    "RIPE NCC",
		"apnic":   "APNIC",
		"lacnic":  "LACNIC",
		"afrinic": "AFRINIC",
	}
	for _, token := range tokens {
		if name := registries[token]; name != "" {
			return name
		}
	}
	return ""
}

func sourceStatusForError(source string, status ReportStatus, err error) IPBGPSourceStatus {
	item := IPBGPSourceStatus{Source: source, Status: status}
	if err != nil {
		item.Error = stableReportError(status, err)
	}
	return item
}

func stableReportError(status ReportStatus, err error) string {
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	switch status {
	case ReportRateLimited:
		return "rate_limited"
	case ReportTimeout:
		return "timeout"
	case ReportUnsupported:
		return "unsupported"
	case ReportMissingFields:
		return "missing_fields"
	default:
		return "request_failed"
	}
}

func sanitizeReportURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return ""
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	return parsed.String()
}

func sanitizeReportURLs(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if sanitized := sanitizeReportURL(value); sanitized != "" {
			result = append(result, sanitized)
		}
	}
	return uniqueSortedStrings(result)
}

func reportStatusForError(err error) ReportStatus {
	if err == nil {
		return ReportAvailable
	}
	if errors.Is(err, ErrRDAPRateLimited) || errors.Is(err, ErrOriginASNRateLimited) {
		return ReportRateLimited
	}
	if errors.Is(err, context.DeadlineExceeded) || netErrTimeout(err) {
		return ReportTimeout
	}
	return ReportError
}

func reportStatusFromRelationship(status RelationshipStatus) ReportStatus {
	switch status {
	case RelationshipAvailable:
		return ReportAvailable
	case RelationshipPartial:
		return ReportPartial
	case RelationshipRateLimited:
		return ReportRateLimited
	case RelationshipTimeout:
		return ReportTimeout
	case RelationshipMissingFields:
		return ReportMissingFields
	case RelationshipUnsupported:
		return ReportUnsupported
	default:
		return ReportError
	}
}

func aggregateReportStatus(sources []IPBGPSourceStatus) ReportStatus {
	if len(sources) == 0 {
		return ReportUnsupported
	}
	hasAvailable := false
	var first ReportStatus
	for _, source := range sources {
		if source.Status == ReportAvailable {
			hasAvailable = true
			continue
		}
		if first == "" {
			first = source.Status
		}
	}
	if first == "" {
		return ReportAvailable
	}
	if hasAvailable {
		return ReportPartial
	}
	for _, source := range sources {
		if source.Status != first {
			return ReportPartial
		}
	}
	return first
}
