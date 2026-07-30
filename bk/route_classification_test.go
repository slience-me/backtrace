package backtrace

import "testing"

func routeFixture(asns ...string) []RouteHopEvidence {
	hops := make([]RouteHopEvidence, 0, len(asns))
	for index, asn := range asns {
		hops = append(hops, RouteHopEvidence{Distance: index + 1, ASNs: []string{asn}})
	}
	return hops
}

func TestClassifyTelecomRequiresOrderedRepeatedEvidence(t *testing.T) {
	tests := []struct {
		name string
		asns []string
		code string
		rank int
	}{
		{name: "single CN2 hop", asns: []string{"AS4809", "AS4134"}, code: "ct_cn2_mixed", rank: 3},
		{name: "GIA with delivery hop", asns: []string{"AS4809", "AS4809", "AS4134"}, code: "ct_cn2_gia", rank: 5},
		{name: "CN2 then 163 backbone", asns: []string{"AS4809", "AS4809", "AS4134", "AS4134"}, code: "ct_cn2_mixed", rank: 3},
		{name: "163 before CN2", asns: []string{"AS4134", "AS4809", "AS4809"}, code: "ct_cn2_gt", rank: 3},
		{name: "single destination hop", asns: []string{"AS4134"}, code: "ct_destination_only", rank: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := ClassifyReturnRoute("CT", routeFixture(test.asns...))
			if result.Code != test.code || result.Rank != test.rank {
				t.Fatalf("ClassifyReturnRoute() = %+v, want code=%s rank=%d", result, test.code, test.rank)
			}
		})
	}
}

func TestClassifyUnicomAddsCUGAndProtectsDestinationHop(t *testing.T) {
	tests := []struct {
		asns []string
		code string
	}{
		{asns: []string{"AS9929", "AS9929", "AS4837"}, code: "cu_9929"},
		{asns: []string{"AS4837", "AS9929"}, code: "cu_9929_mixed"},
		{asns: []string{"AS10099"}, code: "cu_cug"},
		{asns: []string{"AS4837"}, code: "cu_destination_only"},
	}
	for _, test := range tests {
		result := ClassifyReturnRoute("CU", routeFixture(test.asns...))
		if result.Code != test.code {
			t.Fatalf("ClassifyReturnRoute(%v) = %+v, want %s", test.asns, result, test.code)
		}
	}
}

func TestClassifyMobileUsesOrderedCMIN2Evidence(t *testing.T) {
	if result := ClassifyReturnRoute("CM", routeFixture("AS58807", "AS9808")); result.Code != "cm_cmin2" {
		t.Fatalf("CMIN2 route = %+v", result)
	}
	if result := ClassifyReturnRoute("CM", routeFixture("AS58453", "AS58807")); result.Code != "cm_cmin2_mixed" {
		t.Fatalf("mixed CMIN2 route = %+v", result)
	}
	if result := ClassifyReturnRoute("CM", routeFixture("AS9808")); result.Code != "cm_cmnet" {
		t.Fatalf("CMNET route = %+v", result)
	}
}

func TestCombineRouteClassificationsDowngradesDynamicDisagreement(t *testing.T) {
	result := combineRouteClassifications("CU", []RouteClassification{
		ClassifyReturnRoute("CU", routeFixture("AS9929")),
		ClassifyReturnRoute("CU", routeFixture("AS4837", "AS4837")),
	})
	if result.Code != "cu_dynamic_mixed" || result.Confidence != routeConfidenceMixed || result.Rank != 3 {
		t.Fatalf("combined route = %+v", result)
	}
}
