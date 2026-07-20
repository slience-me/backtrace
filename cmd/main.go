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
	"sync"
	"time"

	"github.com/oneclickvirt/backtrace/bgptools"
	backtrace "github.com/oneclickvirt/backtrace/bk"
	"github.com/oneclickvirt/backtrace/model"
	"github.com/oneclickvirt/backtrace/utils"
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
	deep        bool
	specifiedIP string
	timeout     time.Duration
}

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
	set.BoolVar(&options.deep, "deep", false, "Fetch geofeed and enable WHOIS fallback")
	set.DurationVar(&options.timeout, "timeout", 15*time.Second, "Structured report timeout")
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

func main() {
	go func() {
		resp, err := http.Get("https://hits.spiritlhl.net/backtrace.svg?action=hit&title=Hits&title_bg=%23555555&count_bg=%230eecf8&edge_flat=false")
		if err == nil && resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}()
	var options cliOptions
	backtraceFlag := newBacktraceFlagSet(&options)
	if err := backtraceFlag.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if !options.jsonOutput {
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
	if err := validateStructuredOptions(options); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
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
			fmt.Fprintf(os.Stderr, "structured report failed: %v\n", err)
			os.Exit(1)
		}
		return
	}
	info := IpInfo{}
	if options.showIPInfo {
		rsp, err := http.Get("http://ipinfo.io")
		if err != nil {
			fmt.Printf("get ip info err %v \n", err.Error())
		} else {
			defer rsp.Body.Close()
			err = json.NewDecoder(rsp.Body).Decode(&info)
			if err != nil {
				fmt.Printf("json decode err %v \n", err.Error())
			} else {
				fmt.Println(Green("国家: ") + White(info.Country) + Green(" 城市: ") + White(info.City) +
					Green(" 服务商: ") + Blue(info.Org))
			}
		}
	}
	preCheck := utils.CheckPublicAccess(3 * time.Second)
	if !preCheck.Connected {
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
		fmt.Print(results.bgpResult)
	}
	if results.backtraceResult != "" {
		fmt.Printf("%s\n", results.backtraceResult)
	}
	fmt.Println(Yellow("准确线路自行查看详细路由，本测试结果仅作参考"))
	fmt.Println(Yellow("同一目标地址多个线路时，检测可能已越过汇聚层，除第一个线路外，后续信息可能无效"))
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		fmt.Println("Press Enter to exit...")
		fmt.Scanln()
	}
}

func validateStructuredOptions(options cliOptions) error {
	if options.deep && !options.jsonOutput {
		return fmt.Errorf("-deep requires -json or -structured")
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

func writeStructuredReport(ctx context.Context, output io.Writer, ip string, config bgptools.IPBGPReportConfig, query func(context.Context, string, bgptools.IPBGPReportConfig) (*bgptools.IPBGPReport, error)) error {
	report, err := query(ctx, ip, config)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
