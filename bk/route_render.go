package backtrace

import (
	"fmt"
	"strings"

	"github.com/oneclickvirt/backtrace/model"
	. "github.com/oneclickvirt/defaultset"
)

// RenderRouteReport preserves the original compact one-target-per-line style.
// Detailed hop statistics remain available in RouteReport JSON instead of
// expanding the terminal section.
func RenderRouteReport(report RouteReport) string {
	var builder strings.Builder
	for _, target := range report.Targets {
		var rendered string
		switch {
		case target.Status != RouteProbeAvailable:
			rendered = Red("检测不到回程路由节点的IP地址")
		default:
			rendered = renderLegacyRouteLabels(target)
		}
		addressWidth := 15
		if target.Target.IPVersion == "v6" {
			addressWidth = 24
		}
		builder.WriteString(fmt.Sprintf("%v %-*s %v\n", target.Target.Name, addressWidth, target.Target.Address, rendered))
	}
	return strings.TrimSuffix(builder.String(), "\n")
}

// renderLegacyRouteLabels keeps the original terminal contract: every known
// carrier ASN observed in the trace remains visible. The conservative
// Classification is retained for JSON consumers, but its evidence-oriented
// fallback labels must not replace the classic human-readable route result.
func renderLegacyRouteLabels(target RouteTargetReport) string {
	asns := uniqueStrings(target.ObservedASNs)
	hasAS4134 := containsString(asns, "AS4134")
	hasAS4809 := containsString(asns, "AS4809")

	ordered := make([]string, 0, len(asns)+1)
	if hasAS4809 {
		if hasAS4134 {
			ordered = append(ordered, "AS4809b")
		} else {
			ordered = append(ordered, "AS4809a")
		}
	}
	ordered = append(ordered, asns...)

	seenLabels := make(map[string]struct{})
	labels := make([]string, 0, len(ordered))
	for _, asn := range ordered {
		if asn == "AS4809" {
			continue
		}
		label := model.M[asn]
		if label == "" {
			continue
		}
		if _, exists := seenLabels[label]; exists {
			continue
		}
		seenLabels[label] = struct{}{}
		switch asn {
		case "AS9929", "AS4809a", "AS23764":
			labels = append(labels, DarkGreen(label))
		case "AS4809b", "AS58807":
			labels = append(labels, Green(label))
		default:
			labels = append(labels, White(label))
		}
	}
	if len(labels) > 0 {
		return strings.Join(labels, " ")
	}

	// Reports produced by older API clients may contain only Classification.
	if target.Classification.Confidence != routeConfidenceInconclusive && target.Classification.Label != "" {
		switch {
		case target.Classification.Rank >= 4:
			return DarkGreen(target.Classification.Label)
		case target.Classification.Rank == 3:
			return Green(target.Classification.Label)
		default:
			return White(target.Classification.Label)
		}
	}
	return Red("检测不到已知线路的ASN")
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToUpper(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
