package backtrace

import (
	"fmt"
	"strings"

	. "github.com/oneclickvirt/defaultset"
)

// RenderRouteReport preserves the original compact one-target-per-line style.
// Detailed hop statistics remain available in RouteReport JSON instead of
// expanding the terminal section.
func RenderRouteReport(report RouteReport) string {
	var builder strings.Builder
	for _, target := range report.Targets {
		label := target.Classification.Label
		if label == "" {
			label = "线路证据不足"
		}
		var rendered string
		switch {
		case target.Status != RouteProbeAvailable:
			rendered = Red("检测不到回程路由节点的IP地址")
		case target.Classification.Confidence == routeConfidenceInconclusive:
			rendered = Red(label)
		case target.Classification.Rank >= 4:
			rendered = DarkGreen(label)
		case target.Classification.Rank == 3:
			rendered = Green(label)
		default:
			rendered = White(label)
		}
		addressWidth := 15
		if target.Target.IPVersion == "v6" {
			addressWidth = 24
		}
		builder.WriteString(fmt.Sprintf("%v %-*s %v\n", target.Target.Name, addressWidth, target.Target.Address, rendered))
	}
	return strings.TrimSuffix(builder.String(), "\n")
}
