package bgptools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalidIPAddress     = errors.New("invalid IP address")
	ErrRDAPRateLimited      = errors.New("rdap rate limited")
	ErrRDAPResponseTooLarge = errors.New("rdap response too large")
)

type RDAPEntity struct {
	Handle string   `json:"handle,omitempty"`
	Roles  []string `json:"roles,omitempty"`
}

type RDAPRecord struct {
	IP               string       `json:"ip"`
	Handle           string       `json:"handle,omitempty"`
	Name             string       `json:"name,omitempty"`
	Type             string       `json:"type,omitempty"`
	Country          string       `json:"country,omitempty"`
	StartAddress     string       `json:"start_address,omitempty"`
	EndAddress       string       `json:"end_address,omitempty"`
	ParentHandle     string       `json:"parent_handle,omitempty"`
	Prefixes         []string     `json:"prefixes,omitempty"`
	RegistrationDate *time.Time   `json:"registration_date,omitempty"`
	LastChangedDate  *time.Time   `json:"last_changed_date,omitempty"`
	GeofeedURLs      []string     `json:"-"`
	Entities         []RDAPEntity `json:"entities,omitempty"`
	Port43           string       `json:"-"`
	Status           []string     `json:"status,omitempty"`
	Source           string       `json:"source"`
}

func QueryRDAP(ctx context.Context, ip string, client *http.Client, baseURL string) (RDAPRecord, error) {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return RDAPRecord{}, ErrInvalidIPAddress
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	if strings.TrimSpace(baseURL) == "" {
		baseURL = "https://rdap.org/ip/"
	}
	requestURL := strings.TrimRight(baseURL, "/") + "/" + parsed.String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return RDAPRecord{}, errors.New("create RDAP request failed")
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", "oneclickvirt-backtrace-rdap/1")
	response, err := client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return RDAPRecord{}, ctxErr
		}
		return RDAPRecord{}, errors.New("RDAP request failed")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusTooManyRequests {
		return RDAPRecord{}, ErrRDAPRateLimited
	}
	if response.StatusCode != http.StatusOK {
		return RDAPRecord{}, fmt.Errorf("rdap HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil {
		return RDAPRecord{}, errors.New("RDAP response read failed")
	}
	if len(data) > 4<<20 {
		return RDAPRecord{}, ErrRDAPResponseTooLarge
	}
	source := requestURL
	if response.Request != nil && response.Request.URL != nil {
		source = response.Request.URL.String()
	}
	return parseRDAPRecord(parsed.String(), source, data)
}

func parseRDAPRecord(ip, source string, data []byte) (RDAPRecord, error) {
	var payload struct {
		Handle       string   `json:"handle"`
		Name         string   `json:"name"`
		Type         string   `json:"type"`
		Country      string   `json:"country"`
		StartAddress string   `json:"startAddress"`
		EndAddress   string   `json:"endAddress"`
		ParentHandle string   `json:"parentHandle"`
		Port43       string   `json:"port43"`
		Status       []string `json:"status"`
		Events       []struct {
			Action string    `json:"eventAction"`
			Date   time.Time `json:"eventDate"`
		} `json:"events"`
		Links []struct {
			Rel  string `json:"rel"`
			Href string `json:"href"`
			Type string `json:"type"`
		} `json:"links"`
		Entities []struct {
			Handle string   `json:"handle"`
			Roles  []string `json:"roles"`
		} `json:"entities"`
		CIDRs []struct {
			V4Prefix string `json:"v4prefix"`
			V6Prefix string `json:"v6prefix"`
			Length   *int   `json:"length"`
		} `json:"cidr0_cidrs"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return RDAPRecord{}, err
	}
	record := RDAPRecord{
		IP: ip, Handle: payload.Handle, Name: payload.Name, Type: payload.Type,
		Country: payload.Country, StartAddress: payload.StartAddress, EndAddress: payload.EndAddress,
		ParentHandle: payload.ParentHandle, Port43: payload.Port43, Status: payload.Status, Source: "rdap",
	}
	for _, event := range payload.Events {
		switch strings.ToLower(event.Action) {
		case "registration":
			if !event.Date.IsZero() && (record.RegistrationDate == nil || event.Date.Before(*record.RegistrationDate)) {
				value := event.Date
				record.RegistrationDate = &value
			}
		case "last changed", "last update of rdap database":
			if !event.Date.IsZero() && (record.LastChangedDate == nil || event.Date.After(*record.LastChangedDate)) {
				value := event.Date
				record.LastChangedDate = &value
			}
		}
	}
	for _, link := range payload.Links {
		if strings.EqualFold(link.Rel, "geofeed") || strings.Contains(strings.ToLower(link.Type), "geofeed") {
			if href := strings.TrimSpace(link.Href); href != "" {
				record.GeofeedURLs = append(record.GeofeedURLs, href)
			}
		}
	}
	for _, entity := range payload.Entities {
		record.Entities = append(record.Entities, RDAPEntity{Handle: entity.Handle, Roles: entity.Roles})
	}
	for _, cidr := range payload.CIDRs {
		prefix := cidr.V4Prefix
		if prefix == "" {
			prefix = cidr.V6Prefix
		}
		if cidr.Length == nil {
			continue
		}
		if normalized, ok := normalizeRDAPPrefix(ip, prefix, *cidr.Length); ok {
			record.Prefixes = append(record.Prefixes, normalized)
		}
	}
	record.Prefixes = uniqueSortedStrings(record.Prefixes)
	record.GeofeedURLs = uniqueSortedStrings(record.GeofeedURLs)
	return record, nil
}

func normalizeRDAPPrefix(targetIP, prefix string, length int) (string, bool) {
	target := net.ParseIP(strings.TrimSpace(targetIP))
	parsed := net.ParseIP(strings.TrimSpace(prefix))
	if target == nil || parsed == nil || (target.To4() == nil) != (parsed.To4() == nil) {
		return "", false
	}
	bits := 128
	if parsed.To4() != nil {
		bits = 32
	}
	if length < 0 || length > bits {
		return "", false
	}
	_, network, err := net.ParseCIDR(fmt.Sprintf("%s/%d", parsed.String(), length))
	if err != nil {
		return "", false
	}
	if !network.Contains(target) {
		return "", false
	}
	return network.String(), true
}

func uniqueSortedStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
