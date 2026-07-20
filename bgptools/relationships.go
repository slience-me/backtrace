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
	"sort"
	"strconv"
	"strings"
	"time"
)

// RelationshipKind is the relationship of a neighbouring network to the
// target ASN.  RIPEstat does not always publish a direction, in which case a
// neighbour is reported as peer with Inferred=true instead of pretending that
// the direction is known.
type RelationshipKind string

const (
	RelationshipUpstream RelationshipKind = "upstream"
	RelationshipPeer     RelationshipKind = "peer"
	RelationshipIXP      RelationshipKind = "ixp"
)

// RelationshipStatus is deliberately small and stable so callers can render
// a partial report without parsing provider-specific error strings.
type RelationshipStatus string

const (
	RelationshipAvailable     RelationshipStatus = "available"
	RelationshipPartial       RelationshipStatus = "partial"
	RelationshipRateLimited   RelationshipStatus = "rate_limited"
	RelationshipTimeout       RelationshipStatus = "timeout"
	RelationshipMissingFields RelationshipStatus = "missing_fields"
	RelationshipError         RelationshipStatus = "error"
	RelationshipUnsupported   RelationshipStatus = "unsupported"
)

var errRelationshipMissingFields = errors.New("relationship response missing required fields")

// ASNRelationship is a normalized relationship entry.  ASN is empty for an
// IXP that has no ASN in PeeringDB; IXPID and Name remain usable identifiers.
type ASNRelationship struct {
	ASN         string             `json:"asn,omitempty"`
	Name        string             `json:"name,omitempty"`
	Kind        RelationshipKind   `json:"kind"`
	Source      string             `json:"source"`
	Status      RelationshipStatus `json:"status"`
	Power       float64            `json:"power,omitempty"`
	IXPID       string             `json:"ixp_id,omitempty"`
	Inferred    bool               `json:"inferred,omitempty"`
	RateLimited bool               `json:"rate_limited,omitempty"`
	Timeout     bool               `json:"timeout,omitempty"`
}

// RelationshipSourceStatus records the result of each upstream API.  A
// report may be partial when one API is unavailable and the other succeeds.
type RelationshipSourceStatus struct {
	Source      string             `json:"source"`
	Status      RelationshipStatus `json:"status"`
	RateLimited bool               `json:"rate_limited"`
	Timeout     bool               `json:"timeout"`
	Error       string             `json:"error,omitempty"`
}

// ASNRelationshipReport contains normalized upstream, peer and IXP entries.
// SourceStatuses allows callers to distinguish a clean empty result from a
// provider timeout or rate limit.
type ASNRelationshipReport struct {
	TargetASN      string                     `json:"target_asn"`
	Status         RelationshipStatus         `json:"status"`
	RateLimited    bool                       `json:"rate_limited"`
	Timeout        bool                       `json:"timeout"`
	Upstreams      []ASNRelationship          `json:"upstreams,omitempty"`
	Peers          []ASNRelationship          `json:"peers,omitempty"`
	IXPs           []ASNRelationship          `json:"ixps,omitempty"`
	SourceStatuses []RelationshipSourceStatus `json:"sources,omitempty"`
}

// RelationshipConfig controls the public API endpoints.  URLs are explicit
// Go configuration so callers can use local fixtures without environment
// variables.  Empty URLs select the documented public endpoints.
type RelationshipConfig struct {
	Client          *http.Client
	RIPEstatURL     string
	PeeringDBURL    string
	Timeout         time.Duration
	MaxResponseSize int64
}

const (
	defaultRIPEstatURL  = "https://stat.ripe.net/data/asn-neighbours/data.json"
	defaultPeeringDBURL = "https://www.peeringdb.com/api/netixlan"
)

// QueryASNRelationships fetches relationship data from RIPEstat and IXP
// membership data from PeeringDB.  It returns a report even when one source
// fails; only an invalid ASN or caller cancellation is returned as an error.
func QueryASNRelationships(ctx context.Context, asn string, cfg RelationshipConfig) (*ASNRelationshipReport, error) {
	normalized, err := normalizeASN(asn)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 8 * time.Second
	}
	if cfg.MaxResponseSize <= 0 {
		cfg.MaxResponseSize = 4 << 20
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{}
	}
	if strings.TrimSpace(cfg.RIPEstatURL) == "" {
		cfg.RIPEstatURL = defaultRIPEstatURL
	}
	if strings.TrimSpace(cfg.PeeringDBURL) == "" {
		cfg.PeeringDBURL = defaultPeeringDBURL
	}

	report := &ASNRelationshipReport{TargetASN: normalized}
	ripeURL, err := addQuery(cfg.RIPEstatURL, "resource", normalized)
	if err != nil {
		return nil, err
	}
	ripeRaw, ripeStatus, ripeErr := fetchRelationshipJSON(ctx, cfg, "ripestat", ripeURL)
	report.SourceStatuses = append(report.SourceStatuses, sourceStatus("ripestat", ripeStatus, ripeErr))
	if ripeErr == nil {
		entries, parseErr := parseRIPEstatRelationships(ripeRaw, normalized)
		if parseErr != nil {
			ripeStatus = statusForParseError(parseErr)
			report.SourceStatuses[len(report.SourceStatuses)-1] = sourceStatus("ripestat", ripeStatus, parseErr)
		} else {
			for _, entry := range entries {
				if entry.Kind == RelationshipUpstream {
					report.Upstreams = append(report.Upstreams, entry)
				} else {
					report.Peers = append(report.Peers, entry)
				}
			}
		}
	}

	peeringURL, err := addQuery(cfg.PeeringDBURL, "asn", normalized)
	if err != nil {
		return nil, err
	}
	peeringRaw, peeringStatus, peeringErr := fetchRelationshipJSON(ctx, cfg, "peeringdb", peeringURL)
	report.SourceStatuses = append(report.SourceStatuses, sourceStatus("peeringdb", peeringStatus, peeringErr))
	if peeringErr == nil {
		entries, parseErr := parsePeeringDBIXPs(peeringRaw)
		if parseErr != nil {
			peeringStatus = statusForParseError(parseErr)
			report.SourceStatuses[len(report.SourceStatuses)-1] = sourceStatus("peeringdb", peeringStatus, parseErr)
		} else {
			report.IXPs = append(report.IXPs, entries...)
		}
	}

	sortRelationships(report)
	report.Status = aggregateRelationshipStatus(report.SourceStatuses)
	for _, source := range report.SourceStatuses {
		report.RateLimited = report.RateLimited || source.RateLimited
		report.Timeout = report.Timeout || source.Timeout
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	return report, nil
}

// QueryASNRelationshipReport is a descriptive alias for QueryASNRelationships.
func QueryASNRelationshipReport(ctx context.Context, asn string, cfg RelationshipConfig) (*ASNRelationshipReport, error) {
	return QueryASNRelationships(ctx, asn, cfg)
}

func normalizeASN(value string) (string, error) {
	value = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(value)), "AS")
	if value == "" {
		return "", errors.New("ASN cannot be empty")
	}
	n, err := strconv.ParseUint(value, 10, 32)
	if err != nil || n == 0 {
		return "", fmt.Errorf("invalid ASN %q", value)
	}
	return strconv.FormatUint(n, 10), nil
}

func addQuery(rawURL, key, value string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	query := u.Query()
	query.Set(key, value)
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func fetchRelationshipJSON(parent context.Context, cfg RelationshipConfig, source, requestURL string) ([]byte, RelationshipStatus, error) {
	ctx, cancel := context.WithTimeout(parent, cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, RelationshipError, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "oneclickvirt-backtrace-relationships/1")
	resp, err := cfg.Client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || (netErrTimeout(err)) {
			return nil, RelationshipTimeout, err
		}
		return nil, RelationshipError, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, RelationshipRateLimited, fmt.Errorf("%s HTTP %d", source, resp.StatusCode)
	}
	if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusGatewayTimeout {
		return nil, RelationshipTimeout, fmt.Errorf("%s HTTP %d", source, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, RelationshipError, fmt.Errorf("%s HTTP %d", source, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, cfg.MaxResponseSize+1))
	if err != nil {
		return nil, RelationshipError, err
	}
	if int64(len(body)) > cfg.MaxResponseSize {
		return nil, RelationshipError, fmt.Errorf("%s response exceeds %d bytes", source, cfg.MaxResponseSize)
	}
	return body, RelationshipAvailable, nil
}

func netErrTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func sourceStatus(source string, status RelationshipStatus, err error) RelationshipSourceStatus {
	item := RelationshipSourceStatus{
		Source: source, Status: status,
		RateLimited: status == RelationshipRateLimited,
		Timeout:     status == RelationshipTimeout,
	}
	if err != nil {
		item.Error = err.Error()
	}
	return item
}

func statusForParseError(err error) RelationshipStatus {
	if errors.Is(err, errRelationshipMissingFields) {
		return RelationshipMissingFields
	}
	return RelationshipError
}

func aggregateRelationshipStatus(sources []RelationshipSourceStatus) RelationshipStatus {
	available := 0
	for _, source := range sources {
		if source.Status == RelationshipAvailable {
			available++
		}
	}
	if available == len(sources) {
		return RelationshipAvailable
	}
	if available > 0 {
		return RelationshipPartial
	}
	for _, source := range sources {
		if source.Status == RelationshipRateLimited {
			return RelationshipRateLimited
		}
	}
	for _, source := range sources {
		if source.Status == RelationshipTimeout {
			return RelationshipTimeout
		}
	}
	for _, source := range sources {
		if source.Status == RelationshipMissingFields {
			return RelationshipMissingFields
		}
	}
	return RelationshipError
}

type ripeNeighbourResponse struct {
	Data *struct {
		Neighbours json.RawMessage `json:"neighbours"`
	} `json:"data"`
}

type ripeNeighbour struct {
	ASN          json.RawMessage `json:"asn"`
	Name         string          `json:"name"`
	Power        float64         `json:"power"`
	Type         string          `json:"type"`
	Relationship string          `json:"relationship"`
	Direction    string          `json:"direction"`
}

func parseRIPEstatRelationships(payload []byte, targetASN string) ([]ASNRelationship, error) {
	var response ripeNeighbourResponse
	if err := json.Unmarshal(payload, &response); err != nil {
		return nil, err
	}
	if response.Data == nil || len(response.Data.Neighbours) == 0 || string(response.Data.Neighbours) == "null" {
		return nil, errRelationshipMissingFields
	}
	var neighbours []ripeNeighbour
	if err := json.Unmarshal(response.Data.Neighbours, &neighbours); err != nil {
		return nil, errRelationshipMissingFields
	}
	var result []ASNRelationship
	for _, neighbour := range neighbours {
		asn, err := parseJSONASN(neighbour.ASN)
		if err != nil || asn == targetASN {
			continue
		}
		kind, inferred := relationshipKind(neighbour.Relationship, neighbour.Type, neighbour.Direction)
		result = append(result, ASNRelationship{
			ASN: asn, Name: strings.TrimSpace(neighbour.Name), Kind: kind,
			Source: "ripestat", Status: RelationshipAvailable,
			Power: neighbour.Power, Inferred: inferred,
		})
	}
	return dedupeRelationships(result), nil
}

func relationshipKind(values ...string) (RelationshipKind, bool) {
	for _, value := range values {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "upstream", "provider", "transit":
			return RelationshipUpstream, false
		case "peer", "peering", "customer", "downstream":
			return RelationshipPeer, false
		case "ixp", "internet exchange", "exchange":
			return RelationshipIXP, false
		}
	}
	return RelationshipPeer, true
}

func parseJSONASN(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", errors.New("missing ASN")
	}
	var value string
	if raw[0] == '"' {
		if err := json.Unmarshal(raw, &value); err != nil {
			return "", err
		}
	} else {
		var number json.Number
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.UseNumber()
		if err := decoder.Decode(&number); err != nil {
			return "", err
		}
		value = number.String()
	}
	return normalizeASN(value)
}

func dedupeRelationships(values []ASNRelationship) []ASNRelationship {
	seen := make(map[string]ASNRelationship, len(values))
	for _, value := range values {
		key := string(value.Kind) + ":" + value.ASN + ":" + value.IXPID
		if previous, ok := seen[key]; !ok || previous.Name == "" && value.Name != "" {
			seen[key] = value
		}
	}
	result := make([]ASNRelationship, 0, len(seen))
	for _, value := range seen {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Kind != result[j].Kind {
			return result[i].Kind < result[j].Kind
		}
		if result[i].ASN != result[j].ASN {
			return result[i].ASN < result[j].ASN
		}
		return result[i].IXPID < result[j].IXPID
	})
	return result
}

type peeringDBResponse struct {
	Data json.RawMessage `json:"data"`
}

func parsePeeringDBIXPs(payload []byte) ([]ASNRelationship, error) {
	var response peeringDBResponse
	if err := json.Unmarshal(payload, &response); err != nil {
		return nil, err
	}
	if len(response.Data) == 0 || string(response.Data) == "null" {
		return nil, errRelationshipMissingFields
	}
	var records []map[string]json.RawMessage
	if err := json.Unmarshal(response.Data, &records); err != nil {
		return nil, errRelationshipMissingFields
	}
	result := make([]ASNRelationship, 0, len(records))
	for _, record := range records {
		id := firstString(record, "ix_id", "ixlan_id", "id")
		name := firstString(record, "name", "ix_name")
		if nested, ok := record["ixlan"]; ok {
			var object map[string]json.RawMessage
			if json.Unmarshal(nested, &object) == nil {
				if id == "" {
					id = firstString(object, "ix_id", "id")
				}
				if name == "" {
					name = firstString(object, "name", "name_long")
				}
			}
		}
		if nested, ok := record["ix"]; ok {
			var object map[string]json.RawMessage
			if json.Unmarshal(nested, &object) == nil {
				if id == "" {
					id = firstString(object, "id", "ix_id")
				}
				if name == "" {
					name = firstString(object, "name", "name_long")
				}
			}
		}
		if id == "" && name == "" {
			continue
		}
		result = append(result, ASNRelationship{
			Name: name, Kind: RelationshipIXP, Source: "peeringdb",
			Status: RelationshipAvailable, IXPID: id,
		})
	}
	return dedupeRelationships(result), nil
}

func firstString(values map[string]json.RawMessage, keys ...string) string {
	for _, key := range keys {
		raw, ok := values[key]
		if !ok {
			continue
		}
		var value string
		if json.Unmarshal(raw, &value) == nil && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
		if number, err := parseJSONASN(raw); err == nil {
			return number
		}
	}
	return ""
}

func sortRelationships(report *ASNRelationshipReport) {
	report.Upstreams = dedupeRelationships(report.Upstreams)
	report.Peers = dedupeRelationships(report.Peers)
	report.IXPs = dedupeRelationships(report.IXPs)
	sort.Slice(report.SourceStatuses, func(i, j int) bool {
		return report.SourceStatuses[i].Source < report.SourceStatuses[j].Source
	})
}
