package backtrace

import (
	_ "embed"
	"net/netip"
	"strings"
)

//go:embed prefix/as4809.txt
var as4809Data string

//go:embed prefix/as4134.txt
var as4134Data string

//go:embed prefix/as9929.txt
var as9929Data string

//go:embed prefix/as10099.txt
var as10099Data string

//go:embed prefix/as4837.txt
var as4837Data string

//go:embed prefix/as58807.txt
var as58807Data string

//go:embed prefix/as9808.txt
var as9808Data string

//go:embed prefix/as58453.txt
var as58453Data string

//go:embed prefix/as23764.txt
var as23764Data string

// ASN -> Prefix strings
var asnPrefixes = map[string][]string{
	"AS4809":  strings.Split(as4809Data, "\n"),  // 电信 CN2 GT/GIA
	"AS4134":  strings.Split(as4134Data, "\n"),  // 电信 163 骨干网
	"AS9929":  strings.Split(as9929Data, "\n"),  // 联通 9929 优质国际线路
	"AS10099": strings.Split(as10099Data, "\n"), // 联通 CUG 国际网络
	"AS4837":  strings.Split(as4837Data, "\n"),  // 联通 AS4837 普通国际线路
	"AS58807": strings.Split(as58807Data, "\n"), // 移动 CMIN2 国际精品网
	"AS9808":  strings.Split(as9808Data, "\n"),  // 移动 CMI（中国移动国际公司）
	"AS58453": strings.Split(as58453Data, "\n"), // 移动国际互联网（CMI/HK）
	"AS23764": strings.Split(as23764Data, "\n"), // 电信 CTGNET/国际出口（可能是CN2-B）
}

// 判断 IPv6 地址是否匹配 ASN 中的某个前缀
func ipv6Asn(ip string) string {
	ip = strings.ToLower(ip)
	address, addressErr := netip.ParseAddr(ip)
	if addressErr != nil || !address.Is6() {
		return ""
	}
	bestASN := ""
	bestSpecificity := -1
	for asn, prefixes := range currentASNPrefixes() {
		for _, prefix := range prefixes {
			prefix = strings.TrimSpace(prefix)
			if prefix == "" {
				continue
			}
			if strings.Contains(prefix, "/") {
				network, networkErr := netip.ParsePrefix(prefix)
				if networkErr == nil && network.Contains(address) &&
					(network.Bits() > bestSpecificity || (network.Bits() == bestSpecificity && asn < bestASN)) {
					bestASN = asn
					bestSpecificity = network.Bits()
				}
				continue
			}
			if strings.HasPrefix(ip, prefix) {
				specificity := prefixHexBits(prefix)
				if specificity > bestSpecificity || (specificity == bestSpecificity && asn < bestASN) {
					bestASN = asn
					bestSpecificity = specificity
				}
			}
		}
	}
	return bestASN
}

func prefixHexBits(prefix string) int {
	bits := 0
	for _, value := range prefix {
		switch {
		case value >= '0' && value <= '9':
			bits += 4
		case value >= 'a' && value <= 'f':
			bits += 4
		}
	}
	return bits
}
