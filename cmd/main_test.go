package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/oneclickvirt/backtrace/bgptools"
	backtrace "github.com/oneclickvirt/backtrace/bk"
	"github.com/oneclickvirt/backtrace/utils"
	"github.com/oneclickvirt/basics/network/resolver"
)

func TestBacktraceStructuredFlagParsing(t *testing.T) {
	var options cliOptions
	set := newBacktraceFlagSet(&options)
	if err := set.Parse([]string{"-structured", "-deep", "-ip", "192.0.2.1", "-timeout", "900ms"}); err != nil {
		t.Fatal(err)
	}
	if !options.jsonOutput || !options.deep || options.specifiedIP != "192.0.2.1" || options.timeout != 900*time.Millisecond {
		t.Fatalf("unexpected options: %+v", options)
	}
}

func TestBacktraceDefaultsPreserveLegacyMode(t *testing.T) {
	var options cliOptions
	if err := newBacktraceFlagSet(&options).Parse(nil); err != nil {
		t.Fatal(err)
	}
	if !options.showIPInfo || options.jsonOutput || options.routeJSON || options.deep || options.ipv6 || options.specifiedIP != "" || options.dnsMode != "auto" || options.timeout != 15*time.Second || options.routeTries != 3 {
		t.Fatalf("legacy defaults changed: %+v", options)
	}
}

func TestBacktraceDNSModeParsing(t *testing.T) {
	var options cliOptions
	if err := newBacktraceFlagSet(&options).Parse([]string{"-dns-mode", "DoT"}); err != nil {
		t.Fatal(err)
	}
	options.dnsMode = strings.ToLower(strings.TrimSpace(options.dnsMode))
	if options.dnsMode != "dot" {
		t.Fatalf("dns mode = %q, want dot", options.dnsMode)
	}
}

func TestConfigureBacktraceResolverScopesBootstrapFallback(t *testing.T) {
	originalConfigure := backtraceDNSConfigureFn
	originalShutdown := backtraceDNSShutdownFn
	originalBootstrapReachable := backtraceDNSBootstrapReachableFn
	t.Cleanup(func() {
		backtraceDNSConfigureFn = originalConfigure
		backtraceDNSShutdownFn = originalShutdown
		backtraceDNSBootstrapReachableFn = originalBootstrapReachable
	})
	tests := []struct {
		name               string
		mode               resolver.Mode
		connected          bool
		bootstrapReachable bool
		configuredStatus   resolver.Status
		wantConfigure      int
		wantBootstrap      int
		wantShutdown       int
	}{
		{
			name:             "connected auto uses normal resolver path",
			mode:             resolver.ModeAuto,
			connected:        true,
			configuredStatus: resolver.Status{Requested: resolver.ModeAuto, Active: resolver.ModeSystem, SystemAvailable: true},
			wantConfigure:    1,
		},
		{
			name:          "offline auto stops when bootstrap is unreachable",
			mode:          resolver.ModeAuto,
			wantBootstrap: 1,
			wantShutdown:  1,
		},
		{
			name:               "offline auto retries after reachable bootstrap",
			mode:               resolver.ModeAuto,
			bootstrapReachable: true,
			configuredStatus:   resolver.Status{Requested: resolver.ModeAuto, Active: resolver.ModeDoH, DoHAvailable: true, Fallback: true, Stack: "IPv4"},
			wantConfigure:      1,
			wantBootstrap:      1,
		},
		{
			name:             "forced DoH bypasses bootstrap gate",
			mode:             resolver.ModeDoH,
			configuredStatus: resolver.Status{Requested: resolver.ModeDoH, Active: resolver.ModeDoH, DoHAvailable: true},
			wantConfigure:    1,
		},
		{
			name:         "system mode never falls back",
			mode:         resolver.ModeSystem,
			wantShutdown: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configureCalls := 0
			bootstrapCalls := 0
			shutdownCalls := 0
			backtraceDNSConfigureFn = func(_ context.Context, config resolver.Config) resolver.Status {
				configureCalls++
				if config.Mode != test.mode {
					t.Fatalf("resolver mode = %q, want %q", config.Mode, test.mode)
				}
				return test.configuredStatus
			}
			backtraceDNSBootstrapReachableFn = func(_ context.Context, config resolver.Config) (string, bool) {
				bootstrapCalls++
				if config.Mode != resolver.ModeAuto {
					t.Fatalf("bootstrap mode = %q, want auto", config.Mode)
				}
				return "IPv4", test.bootstrapReachable
			}
			backtraceDNSShutdownFn = func() { shutdownCalls++ }

			status := configureBacktraceResolver(context.Background(), test.mode, &utils.NetCheckResult{Connected: test.connected})
			if configureCalls != test.wantConfigure || bootstrapCalls != test.wantBootstrap || shutdownCalls != test.wantShutdown {
				t.Fatalf("DNS calls = configure:%d bootstrap:%d shutdown:%d, want configure:%d bootstrap:%d shutdown:%d", configureCalls, bootstrapCalls, shutdownCalls, test.wantConfigure, test.wantBootstrap, test.wantShutdown)
			}
			if test.wantConfigure == 0 && status.Active != resolver.ModeUnavailable {
				t.Fatalf("status = %#v, want unavailable", status)
			}
		})
	}
}

func TestPromoteEncryptedDNSConnectivity(t *testing.T) {
	preCheck := &utils.NetCheckResult{StackType: "None"}
	promoteEncryptedDNSConnectivity(preCheck, resolver.Status{Active: resolver.ModeDoT, Stack: "IPv6"})
	if !preCheck.Connected || !preCheck.HasIPv6 || preCheck.HasIPv4 || preCheck.StackType != "IPv6" {
		t.Fatalf("successful encrypted DNS did not promote network state: %#v", preCheck)
	}
}

func TestBacktraceRouteStructuredFlagParsing(t *testing.T) {
	var options cliOptions
	set := newBacktraceFlagSet(&options)
	if err := set.Parse([]string{"-route-json", "-ipv6", "-route-attempts", "4", "-timeout", "9s"}); err != nil {
		t.Fatal(err)
	}
	if !options.routeJSON || !options.ipv6 || options.routeTries != 4 || options.timeout != 9*time.Second {
		t.Fatalf("unexpected route options: %+v", options)
	}
	if err := validateStructuredOptions(options); err != nil {
		t.Fatalf("valid route options rejected: %v", err)
	}
}

func TestValidateRouteStructuredOptions(t *testing.T) {
	for _, options := range []cliOptions{
		{jsonOutput: true, routeJSON: true, timeout: time.Second, routeTries: 3},
		{routeJSON: true, timeout: 0, routeTries: 3},
		{routeJSON: true, timeout: time.Second, routeTries: 0},
		{routeJSON: true, timeout: time.Second, routeTries: 6},
	} {
		if err := validateStructuredOptions(options); err == nil {
			t.Fatalf("expected invalid route options: %+v", options)
		}
	}
}

func TestWriteStructuredRouteReportKeepsStdoutJSONOnly(t *testing.T) {
	var output bytes.Buffer
	report := backtrace.RouteReport{SchemaVersion: backtrace.RouteReportSchema, Targets: []backtrace.RouteTargetReport{}}
	if err := writeStructuredRouteReport(&output, report); err != nil {
		t.Fatal(err)
	}
	var decoded backtrace.RouteReport
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("stdout is not route JSON: %v (%q)", err, output.String())
	}
	if decoded.SchemaVersion != backtrace.RouteReportSchema {
		t.Fatalf("unexpected route report: %+v", decoded)
	}
}

func TestValidateStructuredOptionsRequiresExplicitModeAndTarget(t *testing.T) {
	tests := []cliOptions{
		{deep: true, timeout: time.Second},
		{jsonOutput: true, timeout: time.Second},
		{jsonOutput: true, specifiedIP: "192.0.2.1"},
	}
	for _, options := range tests {
		if err := validateStructuredOptions(options); err == nil {
			t.Fatalf("expected invalid structured options: %+v", options)
		}
	}
	if err := validateStructuredOptions(cliOptions{jsonOutput: true, deep: true, specifiedIP: "192.0.2.1", timeout: time.Second}); err != nil {
		t.Fatalf("valid structured options rejected: %v", err)
	}
}

func TestWriteStructuredReportKeepsStdoutJSONOnly(t *testing.T) {
	var output bytes.Buffer
	err := writeStructuredReport(context.Background(), &output, "192.0.2.1", bgptools.IPBGPReportConfig{Timeout: time.Second}, func(_ context.Context, ip string, _ bgptools.IPBGPReportConfig) (*bgptools.IPBGPReport, error) {
		return &bgptools.IPBGPReport{IP: ip, Status: bgptools.ReportAvailable, Sources: []bgptools.IPBGPSourceStatus{}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var report bgptools.IPBGPReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("stdout is not JSON: %v (%q)", err, output.String())
	}
	if report.IP != "192.0.2.1" {
		t.Fatalf("unexpected report: %+v", report)
	}
}
