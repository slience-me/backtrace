package utils

import (
	"time"

	basicsutils "github.com/oneclickvirt/basics/utils"
)

type NetCheckResult = basicsutils.NetCheckResult

func CheckPublicAccess(timeout time.Duration) NetCheckResult {
	return basicsutils.CheckPublicAccess(timeout)
}
