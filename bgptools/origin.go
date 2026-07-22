package bgptools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const defaultOriginASNURL = "https://stat.ripe.net/data/network-info/data.json"

var (
	ErrOriginASNMissing     = errors.New("origin ASN response has no usable ASN")
	ErrOriginASNRateLimited = errors.New("origin ASN resolver rate limited")
)

type OriginASNConfig struct {
	Client          *http.Client
	BaseURL         string
	Timeout         time.Duration
	MaxResponseSize int64
}

func ResolveOriginASN(ctx context.Context, ip string) (string, error) {
	return ResolveOriginASNWithConfig(ctx, ip, OriginASNConfig{})
}

func ResolveOriginASNWithConfig(parent context.Context, ip string, config OriginASNConfig) (string, error) {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return "", ErrInvalidIPAddress
	}
	if parent == nil {
		parent = context.Background()
	}
	if config.Timeout <= 0 {
		config.Timeout = 8 * time.Second
	}
	if config.MaxResponseSize <= 0 {
		config.MaxResponseSize = 1 << 20
	}
	if config.Client == nil {
		config.Client = &http.Client{}
	}
	if strings.TrimSpace(config.BaseURL) == "" {
		config.BaseURL = defaultOriginASNURL
	}
	requestURL, err := addQuery(config.BaseURL, "resource", parsed.String())
	if err != nil {
		return "", errors.New("invalid origin ASN source")
	}
	ctx, cancel := context.WithTimeout(parent, config.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return "", errors.New("create origin ASN request failed")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "oneclickvirt-backtrace-origin-asn/1")
	response, err := config.Client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		return "", errors.New("origin ASN request failed")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusTooManyRequests {
		return "", ErrOriginASNRateLimited
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("origin ASN HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, config.MaxResponseSize+1))
	if err != nil {
		return "", errors.New("origin ASN response read failed")
	}
	if int64(len(body)) > config.MaxResponseSize {
		return "", fmt.Errorf("origin ASN response exceeds %d bytes", config.MaxResponseSize)
	}
	var payload struct {
		Status string `json:"status"`
		Data   *struct {
			ASNs []json.RawMessage `json:"asns"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", err
	}
	if status := strings.TrimSpace(payload.Status); status != "" && !strings.EqualFold(status, "ok") {
		return "", fmt.Errorf("origin ASN response status %q", status)
	}
	if payload.Data == nil || len(payload.Data.ASNs) == 0 {
		return "", ErrOriginASNMissing
	}
	for _, raw := range payload.Data.ASNs {
		value, err := originASNValue(raw)
		if err != nil {
			continue
		}
		if normalized, err := normalizeASN(value); err == nil {
			return normalized, nil
		}
	}
	return "", ErrOriginASNMissing
}

func originASNValue(raw json.RawMessage) (string, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return text, nil
	}
	var number json.Number
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&number); err != nil {
		return "", err
	}
	if _, err := strconv.ParseUint(number.String(), 10, 32); err != nil {
		return "", err
	}
	return number.String(), nil
}
