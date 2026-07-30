package backtrace

import "testing"

func TestIPv4ASNBackboneSignatures(t *testing.T) {
	tests := map[string]string{
		"59.43.1.1":     "AS4809",
		"202.97.1.1":    "AS4134",
		"218.105.1.1":   "AS9929",
		"202.77.1.1":    "AS10099",
		"219.158.1.1":   "AS4837",
		"223.118.32.1":  "AS58807",
		"223.119.100.1": "AS58807",
		"223.120.128.1": "AS58807",
		"223.120.127.1": "AS58453",
		"221.183.1.1":   "AS9808",
		"69.194.1.1":    "AS23764",
		"192.0.2.1":     "",
	}
	for address, want := range tests {
		if got := ipv4Asn(address); got != want {
			t.Fatalf("ipv4Asn(%q) = %q, want %q", address, got, want)
		}
	}
}

func TestIPv6ASNRecognizesCUGSnapshot(t *testing.T) {
	if got := ipv6Asn("2401:8a00:1:12::1"); got != "AS10099" {
		t.Fatalf("ipv6Asn(CUG) = %q, want AS10099", got)
	}
}
