package backtrace

import (
	"errors"
	"fmt"
	"net"
)

const defaultPrefixListLimit = 1 << 16

var (
	ErrInvalidPrefix         = errors.New("invalid IPv4 prefix")
	ErrIPv6PrefixUnsupported = errors.New("IPv6 prefix generation is unsupported")
	ErrPrefixListTooLarge    = errors.New("prefix list exceeds limit")
)

// GeneratePrefixList generates the legacy list of /24 address prefixes.  The
// old API cannot return an error, so invalid, IPv6, and over-sized inputs
// return nil.  Callers that need to distinguish these cases should use
// GeneratePrefixListWithLimit.
func GeneratePrefixList(prefix string) []string {
	result, err := GeneratePrefixListWithLimit(prefix, defaultPrefixListLimit)
	if err != nil {
		return nil
	}
	return result
}

// GeneratePrefixListWithLimit generates one entry for every /24-sized block
// covered by an IPv4 CIDR.  Prefixes narrower than /24 are rejected once the
// number of blocks exceeds maxEntries; this keeps /0 and similarly broad
// input from allocating or iterating unbounded data.  A prefix longer than
// /24 still produces the containing block, preserving the legacy behaviour.
func GeneratePrefixListWithLimit(prefix string, maxEntries int) ([]string, error) {
	if maxEntries <= 0 {
		maxEntries = defaultPrefixListLimit
	}
	_, ipNet, err := net.ParseCIDR(prefix)
	if err != nil {
		return nil, fmt.Errorf("%w: %q", ErrInvalidPrefix, prefix)
	}
	maskSize, bits := ipNet.Mask.Size()
	if bits == 128 {
		return nil, fmt.Errorf("%w: %q", ErrIPv6PrefixUnsupported, prefix)
	}
	if bits != 32 || maskSize < 0 || maskSize > 32 || ipNet.IP.To4() == nil {
		return nil, fmt.Errorf("%w: %q", ErrInvalidPrefix, prefix)
	}

	// A /24 block is the output unit used by the original implementation.  A
	// /25-/32 prefix therefore has one containing block, while a /0 would need
	// 2^24 entries and is rejected before allocation.
	blocks := uint64(1)
	if maskSize < 24 {
		blocks = uint64(1) << uint(24-maskSize)
	}
	if blocks > uint64(maxEntries) {
		return nil, fmt.Errorf("%w: %d entries (limit %d)", ErrPrefixListTooLarge, blocks, maxEntries)
	}

	start := binaryIPToInt(ipNet.IP.To4()) &^ uint32(255)
	result := make([]string, 0, int(blocks))
	for index := uint64(0); index < blocks; index++ {
		// The arithmetic is bounded by 2^24 blocks, so this multiplication and
		// addition cannot overflow uint32 for a valid IPv4 network.
		value := start + uint32(index*256)
		result = append(result, fmt.Sprintf("%d.%d.%d", byte(value>>24), byte(value>>16), byte(value>>8)))
	}
	return result, nil
}

// 将IP地址转换为32位整数
func binaryIPToInt(ip net.IP) uint32 {
	return (uint32(ip[0]) << 24) | (uint32(ip[1]) << 16) | (uint32(ip[2]) << 8) | uint32(ip[3])
}

// 将32位整数转换为IP地址
func intToBinaryIP(i uint32) net.IP {
	return net.IPv4(byte(i>>24), byte(i>>16), byte(i>>8), byte(i))
}
