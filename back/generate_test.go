package backtrace

import (
	"errors"
	"reflect"
	"testing"
)

func TestGeneratePrefixListCompatibility(t *testing.T) {
	got := GeneratePrefixList("192.0.2.0/23")
	want := []string{"192.0.2", "192.0.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GeneratePrefixList() = %v, want %v", got, want)
	}

	got = GeneratePrefixList("192.0.2.128/25")
	want = []string{"192.0.2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GeneratePrefixList(/25) = %v, want %v", got, want)
	}
}

func TestGeneratePrefixListRejectsUnsafeInputs(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		want   error
	}{
		{name: "empty", prefix: "", want: ErrInvalidPrefix},
		{name: "invalid", prefix: "not-a-prefix", want: ErrInvalidPrefix},
		{name: "IPv6", prefix: "2001:db8::/32", want: ErrIPv6PrefixUnsupported},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := GeneratePrefixList(test.prefix); got != nil {
				t.Fatalf("legacy API returned %v, want nil", got)
			}
			if _, err := GeneratePrefixListWithLimit(test.prefix, 16); !errors.Is(err, test.want) {
				t.Fatalf("GeneratePrefixListWithLimit() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestGeneratePrefixListLimitsBroadPrefixesBeforeAllocation(t *testing.T) {
	if _, err := GeneratePrefixListWithLimit("0.0.0.0/0", 1024); !errors.Is(err, ErrPrefixListTooLarge) {
		t.Fatalf("GeneratePrefixListWithLimit(/0) error = %v, want %v", err, ErrPrefixListTooLarge)
	}

	got, err := GeneratePrefixListWithLimit("10.0.0.0/16", 256)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 256 || got[0] != "10.0.0" || got[255] != "10.0.255" {
		t.Fatalf("unexpected bounded result: len=%d first=%q last=%q", len(got), got[0], got[len(got)-1])
	}
}
