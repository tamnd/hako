//go:build !darwin && !linux

package sandbox

import (
	"context"
	"fmt"
	"runtime"

	"github.com/tamnd/hako/pkg/policy"
)

func run(ctx context.Context, r *policy.Resolved, c Command) (Result, error) {
	return Result{ExitCode: ExitError},
		fmt.Errorf("sandbox: %s is not supported (darwin and linux only)", runtime.GOOS)
}
