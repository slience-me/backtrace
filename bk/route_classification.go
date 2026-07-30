package backtrace

import "strings"

// RouteHopEvidence is the ordered ASN evidence observed at one responding hop.
// A hop can contain more than one ASN when repeated traces take different paths.
type RouteHopEvidence struct {
	Distance int      `json:"distance"`
	ASNs     []string `json:"asns,omitempty"`
}

// RouteClassification is a conservative classification of a China-carrier
// return route. Code and Confidence are stable machine-readable values; Label
// preserves the compact legacy display used by backtrace and ecs.
type RouteClassification struct {
	Code       string `json:"code"`
	Label      string `json:"label"`
	Confidence string `json:"confidence"`
	Rank       int    `json:"rank"`
	Evidence   string `json:"evidence"`
}

const (
	routeConfidenceConfirmed    = "confirmed"
	routeConfidenceMixed        = "mixed"
	routeConfidenceInconclusive = "inconclusive"
)

// ClassifyReturnRoute classifies ordered return-route evidence. Premium-route
// claims require enough evidence to distinguish a backbone segment from a
// single destination-network delivery hop.
func ClassifyReturnRoute(carrier string, hops []RouteHopEvidence) RouteClassification {
	carrier = normalizeCarrier(carrier)
	switch carrier {
	case "CT":
		return classifyTelecom(hops)
	case "CU":
		return classifyUnicom(hops)
	case "CM":
		return classifyMobile(hops)
	default:
		return inconclusiveClassification("unknown_carrier", "线路证据不足", "unknown carrier")
	}
}

func classifyTelecom(hops []RouteHopEvidence) RouteClassification {
	cn2Index, cn2Hops := routeASNPosition(hops, "AS4809")
	ct163Index, ct163Hops := routeASNPosition(hops, "AS4134")
	ctgIndex, _ := routeASNPosition(hops, "AS23764")
	if cn2Index >= 0 {
		if cn2Hops < 2 {
			return RouteClassification{
				Code: "ct_cn2_mixed", Label: "电信CN2混合 [优质线路]", Confidence: routeConfidenceMixed, Rank: 3,
				Evidence: "only one AS4809 hop; CN2 GIA is not confirmed",
			}
		}
		if ct163Index < 0 || (cn2Index < ct163Index && ct163Hops <= 1) {
			return RouteClassification{
				Code: "ct_cn2_gia", Label: "电信CN2GIA [精品线路]", Confidence: routeConfidenceConfirmed, Rank: 5,
				Evidence: "at least two AS4809 hops precede at most one AS4134 delivery hop",
			}
		}
		if cn2Index < ct163Index {
			return RouteClassification{
				Code: "ct_cn2_mixed", Label: "电信CN2混合 [优质线路]", Confidence: routeConfidenceMixed, Rank: 3,
				Evidence: "AS4809 is followed by multiple AS4134 backbone hops",
			}
		}
		return RouteClassification{
			Code: "ct_cn2_gt", Label: "电信CN2GT  [优质线路]", Confidence: routeConfidenceMixed, Rank: 3,
			Evidence: "AS4134 appears before the AS4809 segment",
		}
	}
	if ctgIndex >= 0 {
		return RouteClassification{
			Code: "ct_ctgnet", Label: "电信CTGNET [精品线路]", Confidence: routeConfidenceConfirmed, Rank: 4,
			Evidence: "AS23764 is present",
		}
	}
	if ct163Index >= 0 {
		if ct163Hops <= 1 {
			return inconclusiveClassification("ct_destination_only", "仅见电信目的网", "only one AS4134 hop")
		}
		return RouteClassification{
			Code: "ct_163", Label: "电信163    [普通线路]", Confidence: routeConfidenceConfirmed, Rank: 2,
			Evidence: "multiple AS4134 hops are present without premium backbone evidence",
		}
	}
	return inconclusiveClassification("ct_unknown", "未见电信骨干", "AS4809, AS23764, and AS4134 are absent")
}

func classifyUnicom(hops []RouteHopEvidence) RouteClassification {
	cu9929Index, _ := routeASNPosition(hops, "AS9929")
	cugIndex, _ := routeASNPosition(hops, "AS10099")
	cu4837Index, cu4837Hops := routeASNPosition(hops, "AS4837")
	if cu9929Index >= 0 {
		if cu4837Index >= 0 && cu4837Index < cu9929Index {
			return RouteClassification{
				Code: "cu_9929_mixed", Label: "联通9929混合 [优质线路]", Confidence: routeConfidenceMixed, Rank: 3,
				Evidence: "AS4837 appears before the AS9929 segment",
			}
		}
		return RouteClassification{
			Code: "cu_9929", Label: "联通9929   [优质线路]", Confidence: routeConfidenceConfirmed, Rank: 5,
			Evidence: "AS9929 is present without an earlier AS4837 segment",
		}
	}
	if cugIndex >= 0 {
		return RouteClassification{
			Code: "cu_cug", Label: "联通CUG    [优质线路]", Confidence: routeConfidenceConfirmed, Rank: 3,
			Evidence: "AS10099 is present without AS9929",
		}
	}
	if cu4837Index >= 0 {
		if cu4837Hops <= 1 {
			return inconclusiveClassification("cu_destination_only", "仅见联通目的网", "only one AS4837 hop")
		}
		return RouteClassification{
			Code: "cu_4837", Label: "联通4837   [普通线路]", Confidence: routeConfidenceConfirmed, Rank: 2,
			Evidence: "multiple AS4837 hops are present without premium backbone evidence",
		}
	}
	return inconclusiveClassification("cu_unknown", "未见联通骨干", "AS9929, AS10099, and AS4837 are absent")
}

func classifyMobile(hops []RouteHopEvidence) RouteClassification {
	cmin2Index, _ := routeASNPosition(hops, "AS58807")
	cmiIndex, _ := routeASNPosition(hops, "AS58453")
	cmnetIndex, _ := routeASNPosition(hops, "AS9808")
	if cmin2Index >= 0 {
		if cmiIndex >= 0 && cmiIndex < cmin2Index {
			return RouteClassification{
				Code: "cm_cmin2_mixed", Label: "移动CMIN2混合 [优质线路]", Confidence: routeConfidenceMixed, Rank: 3,
				Evidence: "AS58453 appears before the AS58807 segment",
			}
		}
		return RouteClassification{
			Code: "cm_cmin2", Label: "移动CMIN2  [精品线路]", Confidence: routeConfidenceConfirmed, Rank: 5,
			Evidence: "AS58807 is present without an earlier AS58453 segment",
		}
	}
	if cmiIndex >= 0 {
		return RouteClassification{
			Code: "cm_cmi", Label: "移动CMI    [普通线路]", Confidence: routeConfidenceConfirmed, Rank: 2,
			Evidence: "AS58453 is present without CMIN2 evidence",
		}
	}
	if cmnetIndex >= 0 {
		return RouteClassification{
			Code: "cm_cmnet", Label: "移动CMNET  [普通线路]", Confidence: routeConfidenceConfirmed, Rank: 2,
			Evidence: "AS9808 is present without international premium backbone evidence",
		}
	}
	return inconclusiveClassification("cm_unknown", "未见移动骨干", "AS58807, AS58453, and AS9808 are absent")
}

// combineRouteClassifications keeps useful results when one attempt is
// inconclusive, but downgrades conflicting confirmed paths to a mixed result.
func combineRouteClassifications(carrier string, values []RouteClassification) RouteClassification {
	known := make([]RouteClassification, 0, len(values))
	for _, value := range values {
		if value.Confidence != routeConfidenceInconclusive {
			known = append(known, value)
		}
	}
	if len(known) == 0 {
		if len(values) > 0 {
			return values[0]
		}
		return inconclusiveClassification(strings.ToLower(normalizeCarrier(carrier))+"_unknown", "线路证据不足", "no classified route evidence")
	}
	best := known[0]
	distinct := map[string]struct{}{best.Code: {}}
	for _, value := range known[1:] {
		distinct[value.Code] = struct{}{}
		if value.Rank > best.Rank {
			best = value
		}
	}
	if len(distinct) == 1 {
		return best
	}
	label := map[string]string{
		"CT": "电信动态混合 [优质线路]",
		"CU": "联通动态混合 [优质线路]",
		"CM": "移动动态混合 [优质线路]",
	}[normalizeCarrier(carrier)]
	if label == "" {
		label = "动态混合线路"
	}
	return RouteClassification{
		Code: strings.ToLower(normalizeCarrier(carrier)) + "_dynamic_mixed", Label: label,
		Confidence: routeConfidenceMixed, Rank: 3,
		Evidence: "successful trace attempts observed conflicting backbone classes",
	}
}

func routeASNPosition(hops []RouteHopEvidence, target string) (int, int) {
	first := -1
	count := 0
	for index, hop := range hops {
		matched := false
		for _, asn := range hop.ASNs {
			if strings.EqualFold(strings.TrimSpace(asn), target) {
				matched = true
				break
			}
		}
		if matched {
			if first < 0 {
				first = index
			}
			count++
		}
	}
	return first, count
}

func normalizeCarrier(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	switch value {
	case "CT", "TELECOM", "电信":
		return "CT"
	case "CU", "UNICOM", "联通":
		return "CU"
	case "CM", "CMCC", "MOBILE", "移动":
		return "CM"
	default:
		return value
	}
}

func inconclusiveClassification(code, label, evidence string) RouteClassification {
	return RouteClassification{
		Code: code, Label: label, Confidence: routeConfidenceInconclusive,
		Rank: 0, Evidence: evidence,
	}
}
