package bgptools

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestQueryIPBGPReportOfflineFixtures(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/rdap/"):
			if got := strings.TrimPrefix(r.URL.Path, "/rdap/"); got != "192.0.2.1" {
				t.Errorf("RDAP IP = %q", got)
			}
			w.Header().Set("Content-Type", "application/rdap+json")
			_, _ = fmt.Fprintf(w, `{"handle":"NET-ARIN-TEST","port43":"whois.arin.net","cidr0_cidrs":[{"v4prefix":"192.0.2.42","length":24}],"events":[{"eventAction":"registration","eventDate":"2020-01-02T03:04:05Z"}],"links":[{"rel":"geofeed","href":%q}]}`, server.URL+"/geofeed.csv")
		case r.URL.Path == "/geofeed.csv":
			_, _ = io.WriteString(w, "192.0.2.0/24,US,US-CA,Example City,\n")
		case r.URL.Path == "/ripe":
			if got := r.URL.Query().Get("resource"); got != "64500" {
				t.Errorf("resource query = %q", got)
			}
			_, _ = io.WriteString(w, `{"data":{"neighbours":[{"asn":64501,"name":"Transit","relationship":"upstream"},{"asn":64502,"name":"Peer","relationship":"peer"}]}}`)
		case r.URL.Path == "/peering":
			_, _ = io.WriteString(w, `{"data":[{"ix_id":7,"name":"Example IX"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	report, err := QueryIPBGPReport(context.Background(), "192.0.2.1", IPBGPReportConfig{
		Timeout:       time.Second,
		RDAPClient:    server.Client(),
		RDAPBaseURL:   server.URL + "/rdap",
		FetchGeofeed:  true,
		GeofeedClient: server.Client(),
		ResolveASN: func(_ context.Context, ip string) (string, error) {
			if ip != "192.0.2.1" {
				t.Fatalf("resolver IP = %q", ip)
			}
			return "AS64500", nil
		},
		Relationships: RelationshipConfig{
			Client:       server.Client(),
			RIPEstatURL:  server.URL + "/ripe",
			PeeringDBURL: server.URL + "/peering",
			Timeout:      time.Second,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != ReportAvailable || report.IP != "192.0.2.1" || report.ASN != "64500" {
		t.Fatalf("unexpected report identity/status: %+v", report)
	}
	if len(report.Prefixes) != 1 || report.Prefixes[0] != "192.0.2.0/24" || report.PrefixSource != "rdap" {
		t.Fatalf("unexpected prefixes: %+v source=%q", report.Prefixes, report.PrefixSource)
	}
	if report.RIR.Name != "ARIN" || report.RIR.Status != ReportAvailable || report.RegistrationDate == nil {
		t.Fatalf("unexpected registry fields: RIR=%+v registration=%v", report.RIR, report.RegistrationDate)
	}
	if len(report.Geofeeds) != 1 || report.Geofeeds[0].Status != ReportAvailable || report.Geofeeds[0].Bytes == 0 {
		t.Fatalf("unexpected geofeed result: %+v", report.Geofeeds)
	}
	if report.Relationships == nil || len(report.Relationships.Upstreams) != 1 || len(report.Relationships.Peers) != 1 || len(report.Relationships.IXPs) != 1 {
		t.Fatalf("unexpected relationships: %+v", report.Relationships)
	}
}

func TestQueryIPBGPReportWHOISFallbackTCPFixture(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	tcpErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			tcpErr <- err
			return
		}
		defer conn.Close()
		query, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			tcpErr <- err
			return
		}
		if strings.TrimSpace(query) != "203.0.113.9" {
			tcpErr <- fmt.Errorf("WHOIS query = %q", query)
			return
		}
		_, err = io.WriteString(conn, "CIDR: 203.0.113.99/24\r\nRegDate: 2021-02-03\r\nSource: ARIN\r\nGeofeed: https://example.test/geofeed.csv\r\n")
		tcpErr <- err
	}()

	rdapServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer rdapServer.Close()

	report, err := QueryIPBGPReport(context.Background(), "203.0.113.9", IPBGPReportConfig{
		Timeout:             time.Second,
		RDAPClient:          rdapServer.Client(),
		RDAPBaseURL:         rdapServer.URL,
		EnableWHOISFallback: true,
		WHOISServer:         listener.Addr().String(),
		WHOISTimeout:        250 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-tcpErr; err != nil {
		t.Fatal(err)
	}
	if report.Status != ReportPartial || report.WHOIS == nil || report.WHOIS.Status != ReportAvailable {
		t.Fatalf("unexpected fallback status: %+v", report)
	}
	if report.PrefixSource != "whois" || len(report.Prefixes) != 1 || report.Prefixes[0] != "203.0.113.0/24" {
		t.Fatalf("unexpected WHOIS prefixes: %+v", report.Prefixes)
	}
	if report.RIR.Name != "ARIN" || report.RIR.Source != "whois" || report.RegistrationDate == nil {
		t.Fatalf("unexpected WHOIS metadata: RIR=%+v registration=%v", report.RIR, report.RegistrationDate)
	}
	if len(report.Geofeeds) != 1 || report.Geofeeds[0].Status != ReportUnsupported {
		t.Fatalf("disabled geofeed fetch was not explicit: %+v", report.Geofeeds)
	}
}

func TestQueryIPBGPReportWHOISTimeoutIsBounded(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = bufio.NewReader(conn).ReadString('\n')
		_, _ = io.Copy(io.Discard, conn)
	}()

	rdapServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer rdapServer.Close()

	started := time.Now()
	report, err := QueryIPBGPReport(context.Background(), "198.51.100.1", IPBGPReportConfig{
		Timeout:             time.Second,
		RDAPClient:          rdapServer.Client(),
		RDAPBaseURL:         rdapServer.URL,
		EnableWHOISFallback: true,
		WHOISServer:         listener.Addr().String(),
		WHOISTimeout:        30 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("WHOIS timeout took %v", elapsed)
	}
	if source := unifiedSourceByName(report, "whois"); source.Status != ReportTimeout {
		t.Fatalf("WHOIS source = %+v, want timeout", source)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TCP fixture did not observe connection cleanup")
	}
}

func TestQueryIPBGPReportResolvesWHOISFromIANABootstrap(t *testing.T) {
	bootstrap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"services":[[["203.0.113.0/24"],["https://rdap.arin.net/registry/"]]]}`)
	}))
	defer bootstrap.Close()
	rdapServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer rdapServer.Close()

	dialed := make(chan string, 1)
	report, err := QueryIPBGPReport(context.Background(), "203.0.113.9", IPBGPReportConfig{
		Timeout:              time.Second,
		RDAPClient:           rdapServer.Client(),
		RDAPBaseURL:          rdapServer.URL,
		EnableWHOISFallback:  true,
		WHOISBootstrapClient: bootstrap.Client(),
		WHOISBootstrapURL:    bootstrap.URL,
		WHOISTimeout:         250 * time.Millisecond,
		WHOISDialContext: func(_ context.Context, _, address string) (net.Conn, error) {
			dialed <- address
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				_, _ = bufio.NewReader(server).ReadString('\n')
				_, _ = io.WriteString(server, "CIDR: 203.0.113.0/24\r\nSource: ARIN\r\n")
			}()
			return client, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := <-dialed; got != "whois.arin.net:43" {
		t.Fatalf("WHOIS address = %q", got)
	}
	if report.WHOIS == nil || report.WHOIS.Status != ReportAvailable || unifiedSourceByName(report, "whois_bootstrap").Status != ReportAvailable {
		t.Fatalf("bootstrap WHOIS evidence missing: %+v", report)
	}
}

func TestQueryIPBGPReportRejectsInvalidInput(t *testing.T) {
	if _, err := QueryIPBGPReport(context.Background(), "", IPBGPReportConfig{}); !errors.Is(err, ErrInvalidIPAddress) {
		t.Fatalf("error = %v, want %v", err, ErrInvalidIPAddress)
	}
}

func TestRIRInferenceRequiresTokenBoundary(t *testing.T) {
	if got := rirNameFromText("https://example.test/stripe-network"); got != "" {
		t.Fatalf("false RIR inference = %q", got)
	}
	if got := rirNameFromText("whois.ripe.net"); got != "RIPE NCC" {
		t.Fatalf("RIR inference = %q, want RIPE NCC", got)
	}
}

func unifiedSourceByName(report *IPBGPReport, name string) IPBGPSourceStatus {
	for _, source := range report.Sources {
		if source.Source == name {
			return source
		}
	}
	return IPBGPSourceStatus{Source: name, Status: ReportError, Error: "not found"}
}
