package backtrace

import (
	"net/netip"
	"strings"
)

func ipv4Asn(ip string) string {
	if strings.Contains(ip, ":") {
		return ipv6Asn(ip)
	}
	address, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || !address.Is4() {
		return ""
	}
	octets := address.As4()
	switch {
	case strings.HasPrefix(ip, "59.43"):
		return "AS4809"
	case strings.HasPrefix(ip, "202.97"):
		return "AS4134"
	case strings.HasPrefix(ip, "218.105") || strings.HasPrefix(ip, "210.51"):
		return "AS9929"
	case strings.HasPrefix(ip, "202.77") || strings.HasPrefix(ip, "43.252") || strings.HasPrefix(ip, "61.14"):
		return "AS10099"
	case strings.HasPrefix(ip, "219.158"):
		return "AS4837"
	case isCMIN2IPv4(octets):
		return "AS58807"
	case strings.HasPrefix(ip, "223.118") || strings.HasPrefix(ip, "223.119") || strings.HasPrefix(ip, "223.120") || strings.HasPrefix(ip, "223.121"):
		return "AS58453"
	case strings.HasPrefix(ip, "221.183") || strings.HasPrefix(ip, "111.24"):
		return "AS9808"
	case strings.HasPrefix(ip, "69.194") || strings.HasPrefix(ip, "203.22"):
		return "AS23764"
	default:
		return ""
	}
}

func isCMIN2IPv4(ip [4]byte) bool {
	if ip[0] != 223 {
		return false
	}
	if ip[1] == 118 && ip[2] == 32 {
		return true
	}
	if ip[1] == 120 && ip[2] >= 128 {
		return true
	}
	if ip[1] != 119 {
		return false
	}
	third := ip[2]
	return third == 8 || third == 9 ||
		(third >= 10 && third <= 15) ||
		(third >= 26 && third <= 29) ||
		(third >= 32 && third <= 37) ||
		third == 74 || third == 75 || third == 88 || third == 89 ||
		third == 100 || third == 252 || third == 253
}
