package backtrace

import (
	"context"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/oneclickvirt/backtrace/model"
)

func testHop(distance int, ip string, rtt time.Duration) *Hop {
	return &Hop{Distance: distance, Nodes: []*Node{{IP: net.ParseIP(ip), RTT: []time.Duration{rtt}}}}
}

func TestRunRouteReportOfflineFixture(t *testing.T) {
	report := RunRouteReport(context.Background(), RouteReportConfig{
		Attempts: 2,
		Timeout:  time.Second,
		Targets:  []RouteTarget{{Name: "测试电信v4", Address: "192.0.2.1", IPVersion: "v4", Carrier: "CT"}},
		Trace: func(_ context.Context, _ net.IP) ([]*Hop, error) {
			return []*Hop{
				testHop(1, "59.43.1.1", 10*time.Millisecond),
				testHop(2, "59.43.2.2", 20*time.Millisecond),
				testHop(3, "202.97.1.1", 30*time.Millisecond),
			}, nil
		},
		AlternativeTarget: func(RouteTarget) []string { return nil },
	})
	if report.SchemaVersion != RouteReportSchema || len(report.Targets) != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
	target := report.Targets[0]
	if target.Status != RouteProbeAvailable || target.SuccessfulAttempts != 2 || target.ValidHops != 3 {
		t.Fatalf("unexpected target status: %+v", target)
	}
	if target.Classification.Code != "ct_cn2_gia" || target.Latency.Samples != 6 || target.Latency.P95MS != 30 {
		t.Fatalf("unexpected route classification or latency: %+v", target)
	}
	if strings.Contains(RenderRouteReport(report), "P95") || !strings.Contains(RenderRouteReport(report), "电信CN2GIA") {
		t.Fatalf("legacy rendering is not compact: %q", RenderRouteReport(report))
	}
}

func TestRunRouteReportUsesAlternativeWithoutExposingItsAddress(t *testing.T) {
	report := RunRouteReport(context.Background(), RouteReportConfig{
		Attempts: 1,
		Timeout:  time.Second,
		Targets:  []RouteTarget{{Name: "测试联通v4", Address: "192.0.2.1", IPVersion: "v4", Carrier: "CU"}},
		Trace: func(_ context.Context, ip net.IP) ([]*Hop, error) {
			if ip.Equal(net.ParseIP("198.51.100.2")) {
				return []*Hop{testHop(1, "202.77.1.1", 12*time.Millisecond)}, nil
			}
			return nil, nil
		},
		AlternativeTarget: func(RouteTarget) []string { return []string{"198.51.100.2"} },
	})
	target := report.Targets[0]
	if !target.Fallback || target.Classification.Code != "cu_cug" {
		t.Fatalf("alternative result = %+v", target)
	}
	if strings.Contains(RenderRouteReport(report), "198.51.100.2") {
		t.Fatalf("legacy output exposed fallback target: %q", RenderRouteReport(report))
	}
}

func TestRenderRouteReportPreservesLegacyAddressWidths(t *testing.T) {
	report := RouteReport{Targets: []RouteTargetReport{
		{
			Target:         RouteTarget{Name: "北京电信v4", Address: "219.141.140.10", IPVersion: "v4", Carrier: "CT"},
			Status:         RouteProbeAvailable,
			Classification: RouteClassification{Label: "电信163    [普通线路]", Confidence: routeConfidenceConfirmed, Rank: 2},
		},
		{
			Target:         RouteTarget{Name: "北京电信v6", Address: "2400:89c0:1053:3::69", IPVersion: "v6", Carrier: "CT"},
			Status:         RouteProbeAvailable,
			Classification: RouteClassification{Label: "电信163    [普通线路]", Confidence: routeConfidenceConfirmed, Rank: 2},
		},
	}}
	rendered := regexp.MustCompile(`\x1b\[[0-9;]*m`).ReplaceAllString(RenderRouteReport(report), "")
	if !strings.Contains(rendered, "北京电信v4 219.141.140.10  电信163") {
		t.Fatalf("IPv4 legacy spacing changed: %q", rendered)
	}
	if !strings.Contains(rendered, "北京电信v6 2400:89c0:1053:3::69     电信163") {
		t.Fatalf("IPv6 legacy spacing changed: %q", rendered)
	}
}

func TestRunRouteReportHonorsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report := RunRouteReport(ctx, RouteReportConfig{
		Attempts:          1,
		Targets:           []RouteTarget{{Name: "测试移动v4", Address: "192.0.2.1", IPVersion: "v4", Carrier: "CM"}},
		Trace:             func(ctx context.Context, _ net.IP) ([]*Hop, error) { return nil, ctx.Err() },
		AlternativeTarget: func(RouteTarget) []string { return nil },
	})
	if report.Targets[0].Status != RouteProbeCanceled {
		t.Fatalf("canceled report = %+v", report.Targets[0])
	}
}

func TestRefreshAlternativeTargetsHonorsCanceledContextAndKeepsValidCache(t *testing.T) {
	alternativeRefreshMu.Lock()
	oldData := model.CachedIcmpData
	oldTargets := model.ParsedIcmpTargets
	oldFetchedAt := model.CachedIcmpDataFetchTime
	model.CachedIcmpData = `[{"province":"北京","isp":"电信","ip_version":"v4","ips":"192.0.2.10"}]`
	model.ParsedIcmpTargets = []model.IcmpTarget{{Province: "北京", ISP: "电信", IPVersion: "v4", IPs: "192.0.2.10"}}
	model.CachedIcmpDataFetchTime = time.Now().Add(-2 * time.Hour)
	alternativeRefreshMu.Unlock()
	t.Cleanup(func() {
		alternativeRefreshMu.Lock()
		defer alternativeRefreshMu.Unlock()
		model.CachedIcmpData = oldData
		model.ParsedIcmpTargets = oldTargets
		model.CachedIcmpDataFetchTime = oldFetchedAt
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	refreshAlternativeTargets(ctx)
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("canceled refresh took %s", elapsed)
	}
	if model.CachedIcmpData == "" || len(model.ParsedIcmpTargets) != 1 {
		t.Fatalf("failed refresh replaced valid cache: data=%q targets=%v", model.CachedIcmpData, model.ParsedIcmpTargets)
	}
}
