package backtrace

import (
	"context"
)

func BackTrace(enableIpv6 bool) string {
	report := RunRouteReport(context.Background(), RouteReportConfig{EnableIPv6: enableIpv6})
	return RenderRouteReport(report)
}
