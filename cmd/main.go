package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/oneclickvirt/backtrace/bgptools"
	backtrace "github.com/oneclickvirt/backtrace/bk"
	"github.com/oneclickvirt/backtrace/model"
	"github.com/oneclickvirt/backtrace/utils"
	"github.com/oneclickvirt/basics/network/resolver"
	. "github.com/oneclickvirt/defaultset"
)

type IpInfo struct {
	Ip      string `json:"ip"`
	City    string `json:"city"`
	Region  string `json:"region"`
	Country string `json:"country"`
	Org     string `json:"org"`
}

type ConcurrentResults struct {
	bgpResult       string
	backtraceResult string
	bgpError        error
	// backtraceError  error
}

type cliOptions struct {
	showVersion bool
	showIPInfo  bool
	help        bool
	ipv6        bool
	jsonOutput  bool
	routeJSON   bool
	deep        bool
	routeTries  int
	specifiedIP string
	dnsMode     string
	timeout     time.Duration
}

var (
	backtraceDNSConfigureFn          = resolver.Configure
	backtraceDNSShutdownFn           = resolver.Shutdown
	backtraceDNSBootstrapReachableFn = resolver.BootstrapReachable
)

func newBacktraceFlagSet(options *cliOptions) *flag.FlagSet {
	set := flag.NewFlagSet("backtrace", flag.ContinueOnError)
	set.BoolVar(&options.help, "h", false, "Show help information")
	set.BoolVar(&options.showVersion, "v", false, "Show version")
	set.BoolVar(&options.showIPInfo, "s", true, "Disabe show ip info")
	set.BoolVar(&model.EnableLoger, "log", false, "Enable logging")
	set.BoolVar(&options.ipv6, "ipv6", false, "Enable ipv6 testing")
	set.StringVar(&options.specifiedIP, "ip", "", "Specify IP address for bgptools")
	set.BoolVar(&options.jsonOutput, "json", false, "Output structured RDAP/BGP report as JSON")
	set.BoolVar(&options.jsonOutput, "structured", false, "Alias for -json")
	set.BoolVar(&options.routeJSON, "route-json", false, "Output structured return-route report as JSON")
	set.BoolVar(&options.deep, "deep", false, "Fetch geofeed and enable WHOIS fallback")
	set.IntVar(&options.routeTries, "route-attempts", 3, "Traceroute attempts per target (1-5)")
	set.DurationVar(&options.timeout, "timeout", 15*time.Second, "Structured or route report timeout")
	set.StringVar(&options.dnsMode, "dns-mode", "auto", "DNS mode (auto, system, doh, or dot)")
	return set
}

func safeGo(wg *sync.WaitGroup, fn func()) {
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
			}
		}()
		fn()
	}()
}

func configureBacktraceResolver(ctx context.Context, mode resolver.Mode, preCheck *utils.NetCheckResult) resolver.Status {
	requested := resolver.ParseMode(string(mode))
	config := resolver.Config{Mode: requested}
	status := resolver.Status{Requested: requested, Active: resolver.ModeUnavailable, Reason: "network unavailable"}
	if preCheck == nil || preCheck.Connected || requested == resolver.ModeDoH || requested == resolver.ModeDoT {
		return backtraceDNSConfigureFn(ctx, config)
	}
	if requested == resolver.ModeAuto {
		if _, reachable := backtraceDNSBootstrapReachableFn(ctx, config); reachable {
			return backtraceDNSConfigureFn(ctx, config)
		}
		status.Reason = "encrypted DNS endpoint unreachable"
	}
	backtraceDNSShutdownFn()
	return status
}

func promoteEncryptedDNSConnectivity(preCheck *utils.NetCheckResult, status resolver.Status) {
	if preCheck == nil || preCheck.Connected || (status.Active != resolver.ModeDoH && status.Active != resolver.ModeDoT) {
		return
	}
	preCheck.Connected = true
	switch status.Stack {
	case "IPv4":
		preCheck.HasIPv4 = true
	case "IPv6":
		preCheck.HasIPv6 = true
	}
	if status.Stack != "" {
		preCheck.StackType = status.Stack
	}
}

func main() {
	var options cliOptions
	backtraceFlag := newBacktraceFlagSet(&options)
	if err := backtraceFlag.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if !options.jsonOutput && !options.routeJSON {
		fmt.Println(Green("Repo:"), Yellow("https://github.com/oneclickvirt/backtrace"))
	}
	if options.help {
		fmt.Printf("Usage: %s [options]\n", os.Args[0])
		backtraceFlag.PrintDefaults()
		return
	}
	if options.showVersion {
		fmt.Println(model.BackTraceVersion)
		return
	}
	options.dnsMode = strings.ToLower(strings.TrimSpace(options.dnsMode))
	if options.dnsMode != "auto" && options.dnsMode != "system" && options.dnsMode != "doh" && options.dnsMode != "dot" {
		fmt.Fprintln(os.Stderr, "dns-mode must be auto, system, doh, or dot")
		os.Exit(2)
	}
	if err := validateStructuredOptions(options); err != nil {
		fmt.Fprintln(os.Stderr, sanitizeErrorText(err.Error()))
		os.Exit(2)
	}
	var preCheck *utils.NetCheckResult
	if !options.jsonOutput && !options.routeJSON {
		check := utils.CheckPublicAccess(3 * time.Second)
		preCheck = &check
	}
	status := configureBacktraceResolver(context.Background(), resolver.ParseMode(options.dnsMode), preCheck)
	promoteEncryptedDNSConnectivity(preCheck, status)
	if status.Active == resolver.ModeDoH || status.Active == resolver.ModeDoT {
		defer backtraceDNSShutdownFn()
	}
	go func() {
		resp, err := http.Get("https://hits.spiritlhl.net/backtrace.svg?action=hit&title=Hits&title_bg=%23555555&count_bg=%230eecf8&edge_flat=false")
		if err == nil && resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}()
	if options.jsonOutput {
		config := bgptools.IPBGPReportConfig{
			Timeout:             options.timeout,
			FetchGeofeed:        options.deep,
			EnableWHOISFallback: options.deep,
			ResolveASN: func(ctx context.Context, ip string) (string, error) {
				return bgptools.ResolveOriginASNWithConfig(ctx, ip, bgptools.OriginASNConfig{Timeout: options.timeout})
			},
		}
		if err := writeStructuredReport(context.Background(), os.Stdout, options.specifiedIP, config, bgptools.QueryIPBGPReport); err != nil {
			fmt.Fprintf(os.Stderr, "structured report failed: %s\n", sanitizeErrorText(err.Error()))
			os.Exit(1)
		}
		return
	}
	if options.routeJSON {
		report := backtrace.RunRouteReport(context.Background(), backtrace.RouteReportConfig{
			EnableIPv6: options.ipv6,
			Attempts:   options.routeTries,
			Timeout:    options.timeout,
		})
		if err := writeStructuredRouteReport(os.Stdout, report); err != nil {
			fmt.Fprintf(os.Stderr, "route report failed: %s\n", sanitizeErrorText(err.Error()))
			os.Exit(1)
		}
		return
	}
	info := IpInfo{}
	if options.showIPInfo {
		rsp, err := http.Get("http://ipinfo.io")
		if err != nil {
			fmt.Printf("get ip info err %s \n", sanitizeErrorText(err.Error()))
		} else {
			defer rsp.Body.Close()
			err = json.NewDecoder(rsp.Body).Decode(&info)
			if err != nil {
				fmt.Printf("json decode err %s \n", sanitizeErrorText(err.Error()))
			} else {
				fmt.Println(Green("国家: ") + White(info.Country) + Green(" 城市: ") + White(info.City) +
					Green(" 服务商: ") + Blue(info.Org))
			}
		}
	}
	if preCheck == nil || !preCheck.Connected {
		fmt.Println(Red("PreCheck IP Type Failed"))
		if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
			fmt.Println("Press Enter to exit...")
			fmt.Scanln()
		}
		return
	}
	var useIPv6 bool
	switch preCheck.StackType {
	case "DualStack":
		useIPv6 = options.ipv6
	case "IPv4":
		useIPv6 = false
	case "IPv6":
		useIPv6 = true
	default:
		fmt.Println(Red("PreCheck IP Type Failed"))
		if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
			fmt.Println("Press Enter to exit...")
			fmt.Scanln()
		}
		return
	}
	results := ConcurrentResults{}
	var wg sync.WaitGroup
	var targetIP string
	if options.specifiedIP != "" {
		targetIP = options.specifiedIP
	} else if info.Ip != "" {
		targetIP = info.Ip
	}
	if targetIP != "" {
		wg.Add(1)
		safeGo(&wg, func() {
			for i := 0; i < 2; i++ {
				result, err := bgptools.GetPoPInfo(targetIP)
				results.bgpError = err
				if err == nil && result.Result != "" {
					results.bgpResult = result.Result
					return
				}
				if i == 0 {
					time.Sleep(3 * time.Second)
				}
			}
		})
	}
	wg.Add(1)
	safeGo(&wg, func() {
		result := backtrace.BackTrace(useIPv6)
		results.backtraceResult = result
	})
	wg.Wait()
	if results.bgpResult != "" {
		fmt.Print(indentLegacyOutput(results.bgpResult))
	}
	if results.backtraceResult != "" {
		fmt.Printf("%s\n", indentLegacyOutput(results.backtraceResult))
	}
	fmt.Println(Yellow("准确线路自行查看详细路由，本测试结果仅作参考"))
	fmt.Println(Yellow("同一目标地址多个线路时，检测可能已越过汇聚层，除第一个线路外，后续信息可能无效"))
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		fmt.Println("Press Enter to exit...")
		fmt.Scanln()
	}
}

func validateStructuredOptions(options cliOptions) error {
	if options.jsonOutput && options.routeJSON {
		return fmt.Errorf("-json and -route-json are mutually exclusive")
	}
	if options.deep && !options.jsonOutput {
		return fmt.Errorf("-deep requires -json or -structured")
	}
	if options.routeJSON {
		if options.timeout <= 0 {
			return fmt.Errorf("route report timeout must be positive")
		}
		if options.routeTries < 1 || options.routeTries > 5 {
			return fmt.Errorf("route attempts must be between 1 and 5")
		}
		return nil
	}
	if !options.jsonOutput {
		return nil
	}
	if options.specifiedIP == "" {
		return fmt.Errorf("structured report requires -ip")
	}
	if options.timeout <= 0 {
		return fmt.Errorf("structured report timeout must be positive")
	}
	return nil
}

func writeStructuredRouteReport(output io.Writer, report backtrace.RouteReport) error {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func writeStructuredReport(ctx context.Context, output io.Writer, ip string, config bgptools.IPBGPReportConfig, query func(context.Context, string, bgptools.IPBGPReportConfig) (*bgptools.IPBGPReport, error)) error {
	report, err := query(ctx, ip, config)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
