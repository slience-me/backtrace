package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/oneclickvirt/backtrace/bgptools"
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
	if !options.showIPInfo || options.jsonOutput || options.deep || options.ipv6 || options.specifiedIP != "" || options.timeout != 15*time.Second {
		t.Fatalf("legacy defaults changed: %+v", options)
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
