package backtrace

import (
	"context"
	"errors"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oneclickvirt/backtrace/model"
)

const RouteReportSchema = "backtrace.routes/v1"

type RouteProbeStatus string

const (
	RouteProbeAvailable   RouteProbeStatus = "available"
	RouteProbeUnavailable RouteProbeStatus = "unavailable"
	RouteProbeTimeout     RouteProbeStatus = "timeout"
	RouteProbeCanceled    RouteProbeStatus = "canceled"
)

// RouteTarget identifies one carrier route without coupling the runner to the
// built-in target registry. This also makes offline fixture tests possible.
type RouteTarget struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	IPVersion string `json:"ip_version"`
	Carrier   string `json:"carrier"`
}

type RouteLatencyStats struct {
	Samples  int     `json:"samples"`
	MinMS    float64 `json:"min_ms"`
	AvgMS    float64 `json:"avg_ms"`
	P50MS    float64 `json:"p50_ms"`
	P95MS    float64 `json:"p95_ms"`
	MaxMS    float64 `json:"max_ms"`
	JitterMS float64 `json:"jitter_ms"`
}

type RouteTargetReport struct {
	Target             RouteTarget         `json:"target"`
	Status             RouteProbeStatus    `json:"status"`
	Protocol           string              `json:"protocol"`
	Attempts           int                 `json:"attempts"`
	SuccessfulAttempts int                 `json:"successful_attempts"`
	ValidHops          int                 `json:"valid_hops"`
	TargetReached      bool                `json:"target_reached"`
	Fallback           bool                `json:"fallback"`
	ObservedASNs       []string            `json:"observed_asns,omitempty"`
	Classification     RouteClassification `json:"classification"`
	Latency            RouteLatencyStats   `json:"hop_rtt"`
	Error              string              `json:"error,omitempty"`
}

type RouteReport struct {
	SchemaVersion string              `json:"schema_version"`
	GeneratedAt   time.Time           `json:"generated_at"`
	DurationMS    int64               `json:"duration_ms"`
	Targets       []RouteTargetReport `json:"targets"`
}

type TraceFunc func(context.Context, net.IP) ([]*Hop, error)
type AlternativeTargetFunc func(RouteTarget) []string

type RouteReportConfig struct {
	EnableIPv6        bool
	Attempts          int
	Timeout           time.Duration
	Targets           []RouteTarget
	Trace             TraceFunc
	AlternativeTarget AlternativeTargetFunc
}

type routeAttempt struct {
	hops     []*Hop
	targetIP net.IP
	fallback bool
	err      error
}

// RunRouteReport executes the built-in China carrier return-route matrix and
// returns deterministic structured results. ICMP traceroute response rates are
// route evidence only and must not be interpreted as application packet loss.
func RunRouteReport(ctx context.Context, config RouteReportConfig) RouteReport {
	started := time.Now()
	if ctx == nil {
		ctx = context.Background()
	}
	if config.Attempts <= 0 {
		config.Attempts = 3
	}
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}
	if config.Trace == nil {
		config.Trace = TraceContext
	}
	usesDefaultAlternatives := config.AlternativeTarget == nil
	if len(config.Targets) == 0 {
		config.Targets = defaultRouteTargets(config.EnableIPv6)
	}
	runCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	StartASNPrefixRefresh()
	if usesDefaultAlternatives {
		refreshDone := make(chan struct{})
		go func() {
			refreshAlternativeTargets(runCtx)
			close(refreshDone)
		}()
		config.AlternativeTarget = func(target RouteTarget) []string {
			select {
			case <-refreshDone:
				return defaultAlternativeTargets(target)
			case <-runCtx.Done():
				return nil
			}
		}
	}
	reports := make([]RouteTargetReport, len(config.Targets))
	type indexedReport struct {
		index  int
		report RouteTargetReport
	}
	results := make(chan indexedReport, len(config.Targets))
	for index, target := range config.Targets {
		go func(index int, target RouteTarget) {
			results <- indexedReport{index: index, report: runRouteTarget(runCtx, target, config)}
		}(index, target)
	}
	received := make([]bool, len(config.Targets))
	receivedCount := 0
	for receivedCount < len(config.Targets) {
		select {
		case result := <-results:
			reports[result.index] = result.report
			if !received[result.index] {
				received[result.index] = true
				receivedCount++
			}
		case <-runCtx.Done():
			for index, target := range config.Targets {
				if received[index] {
					continue
				}
				reports[index] = canceledRouteTarget(target, config.Attempts, runCtx.Err())
			}
			receivedCount = len(config.Targets)
		}
	}
	return RouteReport{
		SchemaVersion: RouteReportSchema,
		GeneratedAt:   time.Now().UTC(),
		DurationMS:    time.Since(started).Milliseconds(),
		Targets:       reports,
	}
}

func runRouteTarget(ctx context.Context, target RouteTarget, config RouteReportConfig) RouteTargetReport {
	report := RouteTargetReport{
		Target: target, Status: RouteProbeUnavailable, Protocol: "icmp",
		Attempts:       config.Attempts,
		Classification: inconclusiveClassification(strings.ToLower(normalizeCarrier(target.Carrier))+"_unknown", "线路证据不足", "no responding trace attempts"),
	}
	attempts := make(chan routeAttempt, config.Attempts)
	for attempt := 0; attempt < config.Attempts; attempt++ {
		go func() {
			attempts <- safeExecuteRouteAttempt(ctx, target, config.Trace, config.AlternativeTarget)
		}()
	}
	successful := make([]routeAttempt, 0, config.Attempts)
	for attempt := 0; attempt < config.Attempts; attempt++ {
		select {
		case result := <-attempts:
			if result.err == nil && len(result.hops) > 0 {
				successful = append(successful, result)
				report.Fallback = report.Fallback || result.fallback
			}
		case <-ctx.Done():
			return canceledRouteTarget(target, config.Attempts, ctx.Err())
		}
	}
	if len(successful) == 0 {
		return report
	}
	report.Status = RouteProbeAvailable
	report.SuccessfulAttempts = len(successful)
	allHops := make([][]*Hop, 0, len(successful))
	classifications := make([]RouteClassification, 0, len(successful)+1)
	latencies := make([]float64, 0)
	for _, attempt := range successful {
		allHops = append(allHops, attempt.hops)
		evidence := routeEvidenceFromHops(attempt.hops)
		classifications = append(classifications, ClassifyReturnRoute(target.Carrier, evidence))
		latencies = append(latencies, routeRTTMilliseconds(attempt.hops)...)
		if routeReachedTarget(attempt.hops, attempt.targetIP) {
			report.TargetReached = true
		}
	}
	merged := mergeHops(allHops)
	mergedEvidence := routeEvidenceFromHops(merged)
	classifications = append(classifications, ClassifyReturnRoute(target.Carrier, mergedEvidence))
	report.ValidHops = len(mergedEvidence)
	report.ObservedASNs = uniqueRouteASNs(mergedEvidence)
	report.Classification = combineRouteClassifications(target.Carrier, classifications)
	report.Latency = calculateRouteLatency(latencies)
	return report
}

func safeExecuteRouteAttempt(ctx context.Context, target RouteTarget, trace TraceFunc, alternatives AlternativeTargetFunc) (result routeAttempt) {
	defer func() {
		if recover() != nil {
			result = routeAttempt{err: errors.New("route probe failed")}
		}
	}()
	return executeRouteAttempt(ctx, target, trace, alternatives)
}

func executeRouteAttempt(ctx context.Context, target RouteTarget, trace TraceFunc, alternatives AlternativeTargetFunc) routeAttempt {
	primary := net.ParseIP(strings.TrimSpace(target.Address))
	if primary == nil {
		return routeAttempt{err: errors.New("invalid route target")}
	}
	hops, err := trace(ctx, primary)
	if err == nil && len(hops) > 0 {
		return routeAttempt{hops: hops, targetIP: primary}
	}
	for _, value := range alternatives(target) {
		candidate := net.ParseIP(strings.TrimSpace(value))
		if candidate == nil || candidate.Equal(primary) {
			continue
		}
		hops, err = trace(ctx, candidate)
		if err == nil && len(hops) > 0 {
			return routeAttempt{hops: hops, targetIP: candidate, fallback: true}
		}
		if ctx.Err() != nil {
			return routeAttempt{err: ctx.Err()}
		}
	}
	if err == nil {
		err = errors.New("route returned no responding hops")
	}
	return routeAttempt{err: err}
}

func canceledRouteTarget(target RouteTarget, attempts int, err error) RouteTargetReport {
	status := RouteProbeTimeout
	message := "route probe timed out"
	if errors.Is(err, context.Canceled) {
		status = RouteProbeCanceled
		message = "route probe canceled"
	}
	return RouteTargetReport{
		Target: target, Status: status, Protocol: "icmp", Attempts: attempts,
		Classification: inconclusiveClassification(strings.ToLower(normalizeCarrier(target.Carrier))+"_unknown", "线路证据不足", message),
		Error:          message,
	}
}

func defaultRouteTargets(enableIPv6 bool) []RouteTarget {
	targets := make([]RouteTarget, 0, len(model.Ipv4s)+len(model.Ipv6s))
	for index, address := range model.Ipv4s {
		targets = append(targets, RouteTarget{
			Name: model.Ipv4Names[index], Address: address, IPVersion: "v4", Carrier: carrierFromTargetName(model.Ipv4Names[index]),
		})
	}
	if enableIPv6 {
		for index, address := range model.Ipv6s {
			targets = append(targets, RouteTarget{
				Name: model.Ipv6Names[index], Address: address, IPVersion: "v6", Carrier: carrierFromTargetName(model.Ipv6Names[index]),
			})
		}
	}
	return targets
}

func carrierFromTargetName(name string) string {
	switch {
	case strings.Contains(name, "电信"):
		return "CT"
	case strings.Contains(name, "联通"):
		return "CU"
	case strings.Contains(name, "移动"):
		return "CM"
	default:
		return ""
	}
}

func routeEvidenceFromHops(hops []*Hop) []RouteHopEvidence {
	result := make([]RouteHopEvidence, 0, len(hops))
	for _, hop := range hops {
		if hop == nil || len(hop.Nodes) == 0 {
			continue
		}
		seen := make(map[string]struct{})
		asns := make([]string, 0, len(hop.Nodes))
		for _, node := range hop.Nodes {
			if node == nil || node.IP == nil {
				continue
			}
			asn := ipv4Asn(node.IP.String())
			if asn == "" {
				continue
			}
			if _, exists := seen[asn]; exists {
				continue
			}
			seen[asn] = struct{}{}
			asns = append(asns, asn)
		}
		result = append(result, RouteHopEvidence{Distance: hop.Distance, ASNs: asns})
	}
	return result
}

func uniqueRouteASNs(hops []RouteHopEvidence) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0)
	for _, hop := range hops {
		for _, asn := range hop.ASNs {
			if _, exists := seen[asn]; exists {
				continue
			}
			seen[asn] = struct{}{}
			result = append(result, asn)
		}
	}
	return result
}

func routeRTTMilliseconds(hops []*Hop) []float64 {
	result := make([]float64, 0)
	for _, hop := range hops {
		if hop == nil {
			continue
		}
		for _, node := range hop.Nodes {
			if node == nil {
				continue
			}
			for _, value := range node.RTT {
				if value >= 0 {
					result = append(result, float64(value)/float64(time.Millisecond))
				}
			}
		}
	}
	return result
}

func calculateRouteLatency(values []float64) RouteLatencyStats {
	if len(values) == 0 {
		return RouteLatencyStats{}
	}
	ordered := append([]float64(nil), values...)
	sort.Float64s(ordered)
	total := 0.0
	for _, value := range values {
		total += value
	}
	jitter := 0.0
	if len(values) > 1 {
		for index := 1; index < len(values); index++ {
			delta := values[index] - values[index-1]
			if delta < 0 {
				delta = -delta
			}
			jitter += delta
		}
		jitter /= float64(len(values) - 1)
	}
	return RouteLatencyStats{
		Samples: len(values), MinMS: ordered[0], AvgMS: total / float64(len(values)),
		P50MS: ordered[percentileIndex(len(ordered), 0.50)], P95MS: ordered[percentileIndex(len(ordered), 0.95)],
		MaxMS: ordered[len(ordered)-1], JitterMS: jitter,
	}
}

func percentileIndex(length int, percentile float64) int {
	if length <= 1 {
		return 0
	}
	index := int(math.Ceil(float64(length)*percentile)) - 1
	if index < 0 {
		return 0
	}
	if index >= length {
		return length - 1
	}
	return index
}

func routeReachedTarget(hops []*Hop, target net.IP) bool {
	if target == nil {
		return false
	}
	for _, hop := range hops {
		if hop == nil {
			continue
		}
		for _, node := range hop.Nodes {
			if node != nil && node.IP != nil && node.IP.Equal(target) {
				return true
			}
		}
	}
	return false
}

var alternativeRefreshMu sync.Mutex

func refreshAlternativeTargets(ctx context.Context) {
	alternativeRefreshMu.Lock()
	defer alternativeRefreshMu.Unlock()
	if model.CachedIcmpData != "" && model.ParsedIcmpTargets != nil && time.Since(model.CachedIcmpDataFetchTime) <= time.Hour {
		return
	}
	data := getDataContext(ctx, model.IcmpTargets)
	if data == "" {
		return
	}
	parsed := parseIcmpTargets(data)
	if len(parsed) == 0 {
		return
	}
	model.CachedIcmpData = data
	model.ParsedIcmpTargets = parsed
	model.CachedIcmpDataFetchTime = time.Now()
}

func defaultAlternativeTargets(target RouteTarget) []string {
	return tryAlternativeIPs(target.Name, target.IPVersion)
}
