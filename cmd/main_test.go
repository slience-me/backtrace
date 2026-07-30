package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/oneclickvirt/backtrace/bgptools"
	backtrace "github.com/oneclickvirt/backtrace/bk"
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
	if !options.showIPInfo || options.jsonOutput || options.routeJSON || options.deep || options.ipv6 || options.specifiedIP != "" || options.timeout != 15*time.Second || options.routeTries != 3 {
		t.Fatalf("legacy defaults changed: %+v", options)
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
